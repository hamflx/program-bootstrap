if not exist dist mkdir dist

cargo +nightly-i686-pc-windows-msvc build --target i686-pc-windows-msvc
cargo +nightly-x86_64-pc-windows-msvc build --target x86_64-pc-windows-msvc

copy target\i686-pc-windows-msvc\debug\program_bootstrap_core.dll dist\program_bootstrap_core-x86.dll
copy target\i686-pc-windows-msvc\debug\program-bootstrap.exe dist\program-bootstrap-x86.exe

copy target\x86_64-pc-windows-msvc\debug\program_bootstrap_core.dll dist\program_bootstrap_core-x64.dll
copy target\x86_64-pc-windows-msvc\debug\program-bootstrap.exe dist\program-bootstrap-x64.exe
