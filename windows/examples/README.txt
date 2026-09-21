Examples.

Each folder holds one runnable thing and the source it runs. Double-click the
.cmd, or run it from a shell. Nothing here needs a checkout, a compiler or an
internet connection, except where the folder says so.

  what-this-machine-does\   whether the runtime is ready, what this program
                            has asked it to do, and how this install starts
                            the supervisor. Reads; changes nothing.

  job-lifecycle\            a job from submitted to cancelled, one command per
                            step: observe, cancel, wait, submit again, retry.
                            This is what an application does through the
                            library, shown one call at a time.

  download-a-file\          openabstractions download fetching a real file
                            through the runtime and proving its digest.
                            Needs the internet. Writes into %TEMP%.

The tools these call live in ..\tools\, and are on PATH if you ticked "Add to
PATH". Every example calls them by full path so it works either way.

Building your own program against these layers is ..\dev\USING.txt. There is no
Python, Go or C++ example here because neither a compiler nor an interpreter is
something this installer put on the machine, and an example that cannot run is
not an example.
