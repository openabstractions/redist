#include <abstraction/config/editor.hpp>
#include <abstraction/facade/resolution.hpp>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            std::cerr << "usage: cpp_probe EXPECTED_SID EXPECTED_PROGRAM\n";
            return 2;
        }
        if (std::getenv("ABSTRACTION_RUNTIME_ENDPOINT")) {
            throw std::runtime_error("ABSTRACTION_RUNTIME_ENDPOINT must be unset");
        }

        const auto deadline = abstraction::ipc::Clock::now() + std::chrono::seconds(5);
        const auto selected = abstraction::ipc::select_runtime(deadline);
        if (selected.principal_kind != 1 || selected.principal != argv[1] || selected.program != argv[2]) {
            throw std::runtime_error("installed runtime identity differs from expected Windows SID/program");
        }

        abstraction::facade::ResolutionClient resolver;
        auto editor = abstraction::facade::resolve_service<abstraction::config::ConfigEditorService>(
            resolver, {}, abstraction::facade::Scope::Local, deadline);
        const auto resolved_server = resolver.server();
        if (!resolved_server || resolved_server->principal_kind != 1 ||
            resolved_server->principal != argv[1] || resolved_server->program != argv[2]) {
            throw std::runtime_error("default discovery did not retain the expected installed runtime identity");
        }
        const auto snapshot = editor->read_user();
        if (snapshot.revision.empty()) {
            throw std::runtime_error("ReadUser returned an empty revision");
        }
        std::cout << "PASS Cpp installed selection, default discovery and config ReadUser\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL cpp installed SDK smoke: " << error.what() << '\n';
        return 1;
    }
}
