# hammer
A simple DLL injector made with Rust

# Features
* DLL injection
* DLL ejection
* Create and inject
* Call exported function
* Unicode natively supported
* x86 and x64 support
* Error handling
* Multiple process support

# TODO
* Make calling exported function an optional parameter for inject and create and inject commands
* Make a Rust library that contains the core functionality
* Add setting debug privileges if necessary
* CLR injection
* Manual Map
* Support injecting x64 DLL's into WoW64
* Stealth methods

# Credits
[pe-rs](https://github.com/jethrogb/pe-rs)<br/>
[winapi-rs](https://github.com/retep998/winapi-rs)<br/>
[widestring-rs](https://github.com/starkat99/widestring-rs)<br/>

__A special thanks to the wonderful community on #rust (irc.mozilla.org)__
__Especially__
* ubsan
* WindowsBunny
* Fenrir
* Arnavion
* I'm sorry, I definitely forgot a couple more
