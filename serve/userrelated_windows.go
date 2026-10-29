package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	identity "github.com/openabstractions/abstraction-identity"
	"golang.org/x/sys/windows"
)

// The upgraded per-user product is named by the incoming package's
// [WIX_UPGRADE_DETECTED]: ProductCode GUIDs separated by semicolons.
// FindRelatedProducts reports products in the installing context only, so each
// one is a per-user unmanaged product of this account. Its InstallLocation is
// the ARPINSTALLLOCATION it recorded (0.1.5 sets it to [APPLICATIONFOLDER]), so
// a predecessor installed into a non-default folder is found where it lives.

const msiContextUserUnmanaged = 2

const (
	errorUnknownProduct  = syscall.Errno(1605)
	errorUnknownProperty = syscall.Errno(1608)
)

var procMsiGetProductInfoEx = windows.NewLazySystemDLL("msi.dll").NewProc("MsiGetProductInfoExW")

const coreUpgradeCode = "{CEEF6550-5E44-4E83-8E18-A855C9D941CA}"

// MSI owns the UpgradeCode relation. Only product codes returned by its native
// resolver are passed through the existing registration/folder reader.
func installedCoreProducts() ([]string, error) {
	proc := windows.NewLazySystemDLL("msi.dll").NewProc("MsiEnumRelatedProductsW")
	if err := proc.Find(); err != nil {
		return nil, err
	}
	upgrade, err := windows.UTF16PtrFromString(coreUpgradeCode)
	if err != nil {
		return nil, err
	}
	var codes []string
	for index := uint32(0); ; index++ {
		var code [39]uint16
		result, _, callErr := proc.Call(uintptr(unsafe.Pointer(upgrade)), 0, uintptr(index), uintptr(unsafe.Pointer(&code[0])))
		if result == uintptr(windows.ERROR_NO_MORE_ITEMS) {
			return codes, nil
		}
		if result != 0 {
			return nil, msiError(result, callErr)
		}
		codes = append(codes, windows.UTF16ToString(code[:]))
	}
}

func installedCoreFolders(info productInfoFunc, enumerate func() ([]string, error), canonical func() (string, error)) ([]string, []string, error) {
	codes, err := enumerate()
	if err != nil {
		return nil, nil, err
	}
	if len(codes) == 0 {
		return nil, nil, nil
	}
	products, err := relatedProducts(strings.Join(codes, ";"), info)
	if err != nil {
		return nil, nil, err
	}
	folder, err := canonical()
	if err != nil {
		return nil, nil, err
	}
	return upgradeFolders(folder, products)
}

var productCodePattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// productInfoFunc reads one product property for the current user's per-user
// unmanaged instance.
type productInfoFunc func(code, property string) (string, error)

type relatedProduct struct {
	code, location, version string
}

const msiContextMachine = 4

// msiProductInfo is MsiGetProductInfoExW with the current user and the per-user
// unmanaged context. It only reads registration.
func msiProductInfo(code, property string) (string, error) {
	return msiProductInfoIn(msiContextUserUnmanaged, code, property)
}

// msiMachineProductInfo reads a per-machine product's registration.
func msiMachineProductInfo(code, property string) (string, error) {
	return msiProductInfoIn(msiContextMachine, code, property)
}

func msiProductInfoIn(context uintptr, code, property string) (string, error) {
	if err := procMsiGetProductInfoEx.Find(); err != nil {
		return "", err
	}
	c, err := windows.UTF16PtrFromString(code)
	if err != nil {
		return "", err
	}
	p, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return "", err
	}
	var size uint32
	r, _, callErr := procMsiGetProductInfoEx.Call(uintptr(unsafe.Pointer(c)), 0, context,
		uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", msiError(r, callErr)
	}
	buf := make([]uint16, size+1)
	size = uint32(len(buf))
	r, _, callErr = procMsiGetProductInfoEx.Call(uintptr(unsafe.Pointer(c)), 0, context,
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", msiError(r, callErr)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// msiError is the MSI return code, which errors.Is matches, with the call's
// last error added when it names a different failure.
func msiError(code uintptr, lastErr error) error {
	status := syscall.Errno(code)
	if errno, ok := lastErr.(syscall.Errno); !ok || errno == 0 || errno == status {
		return status
	}
	return fmt.Errorf("%w (last error: %v)", status, lastErr)
}

func relatedProductCodes(list string) ([]string, error) {
	var codes []string
	seen := map[string]bool{}
	for _, code := range strings.Split(list, ";") {
		if !productCodePattern.MatchString(code) {
			return nil, fmt.Errorf("related products %q are not ProductCode GUIDs separated by semicolons", list)
		}
		code = strings.ToUpper(code)
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	return codes, nil
}

// relatedProducts reads each related product's version and recorded folder. A
// product that is not registered for this account means the upgrade detection
// and the registration disagree, and nothing can be targeted safely.
func relatedProducts(list string, info productInfoFunc) ([]relatedProduct, error) {
	codes, err := relatedProductCodes(list)
	if err != nil {
		return nil, err
	}
	var out []relatedProduct
	for _, code := range codes {
		version, err := info(code, "VersionString")
		if errors.Is(err, errorUnknownProduct) {
			return nil, fmt.Errorf("related product %s is not installed for this account", code)
		}
		if err != nil {
			return nil, fmt.Errorf("read the version of related product %s: %w", code, err)
		}
		location, err := info(code, "InstallLocation")
		if errors.Is(err, errorUnknownProperty) {
			location, err = "", nil
		}
		if err != nil {
			return nil, fmt.Errorf("read the install location of related product %s: %w", code, err)
		}
		out = append(out, relatedProduct{code: code, location: location, version: version})
	}
	return out, nil
}

// upgradeFolders is the incoming package's folder and every related product's
// recorded folder, each validated and listed once. A product with no recorded
// folder is named in a note.
func upgradeFolders(folder string, related []relatedProduct) ([]string, []string, error) {
	root, err := userInstallFolder(folder)
	if err != nil {
		return nil, nil, err
	}
	folders := []string{root}
	var notes []string
	for _, p := range related {
		if p.location == "" {
			notes = append(notes, fmt.Sprintf("related product %s %s records no install location; only %s is covered", p.code, p.version, root))
			continue
		}
		location, err := userInstallFolder(p.location)
		if err != nil {
			return nil, nil, fmt.Errorf("related product %s: %w", p.code, err)
		}
		if !containsFolder(folders, location) {
			folders = append(folders, location)
		}
	}
	return folders, notes, nil
}

// userInstallFolder accepts the MSI-formatted install folder. The installer
// passes "[APPLICATIONFOLDER]." so the property's trailing backslash does not
// escape the closing quote; Clean removes the dot.
func userInstallFolder(folder string) (string, error) {
	if strings.ContainsRune(folder, '"') {
		return "", fmt.Errorf("install folder %q contains a quote; the command line was split incorrectly", folder)
	}
	if !filepath.IsAbs(folder) {
		return "", fmt.Errorf("install folder %q is not an absolute path", folder)
	}
	clean := filepath.Clean(folder)
	if filepath.Dir(clean) == clean {
		return "", fmt.Errorf("install folder %q is a volume root; refusing to cover every folder on it", folder)
	}
	path, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return "", err
	}
	attributes, err := windows.GetFileAttributes(path)
	if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("install folder %q is a reparse point; choose a regular local folder in the installer, such as a new folder under Program Files", folder)
	}
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return "", fmt.Errorf("inspect install folder %q: %w", folder, err)
	}
	return longPath(clean), nil
}

// containsFolder reports whether folders already lists folder: by file
// identity when both exist (identity.SameFile), and by name when either is
// still to be created, as the incoming package's folder can be
// (identity.SamePathName).
func containsFolder(folders []string, folder string) bool {
	for _, f := range folders {
		if same, err := identity.SameFile(f, folder); err == nil {
			if same {
				return true
			}
			continue
		}
		if identity.SamePathName(strings.TrimRight(f, `\/`), strings.TrimRight(folder, `\/`)) {
			return true
		}
	}
	return false
}
