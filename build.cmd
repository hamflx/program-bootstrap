if not exist dist mkdir dist

cd packages\shellcode
cargo +nightly-i686-pc-windows-msvc build --target i686-pc-windows-msvc || exit 1
cargo +nightly-x86_64-pc-windows-msvc build --target x86_64-pc-windows-msvc || exit 1

cd ..\..
cargo run -p shellcode-gen || exit 1

cargo +nightly-i686-pc-windows-msvc build --target i686-pc-windows-msvc -p program-bootstrap -p program-bootstrap-core || exit 1

copy target\i686-pc-windows-msvc\debug\program_bootstrap_core.dll dist\program_bootstrap_core-x86.dll
copy target\i686-pc-windows-msvc\debug\program-bootstrap.exe dist\program-bootstrap-x86.exe

copy libs\wow64ext.dll dist\wow64ext.dll
