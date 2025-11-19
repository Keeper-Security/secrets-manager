# GUIDE : Create and Publish a Rust Library

Steps Involved: 
1. Install Rust
2. Create a Library
3. Publish the Library to [crates.io](https::/crates.io/)
4. Optionally check with git
5. Usage of published library in other projects

### Installing rust
 
Rust can be installed using the official guide mentioned in [Rust installation guide](https://www.rust-lang.org/tools/install)

Prerequisite : Have curl installed.
Ideal case commands to run:
> sudo apt update

> sudo apt install curl

> curl --version

> curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

After installing Rust using the curl proto link mentioned above, please check that the Rust is available on local machine.

> rustc –version 

> cargo –version 

> rustup –version
 

### Creating a Library (optional/ just for reference)
We can use the current package as library.

To build a new library, we can use the [cargo](https://doc.rust-lang.org/cargo/) tool.

> cargo init --lib <library_name>

Create a sample public function/module in the library.

Details of the library are in `Cargo.toml` file which is created by cargo when we create the new library


### Publishing the library to [crates.io](https::/crates.io/)
* In order to publish the rust library to crates.io, one must have an active account on crates.io \(preferably logged in with ‘GitHub’\)
* An account token is required in order to publish, which can be generated from the ‘Account Settings’ section on the crates.io account
* Open terminal in project directory (in same folder as Cargo.toml) and run the command mentioned below
   > Cargo login
* This command will prompt you to enter the token. You can use your account token here.
* After successful login, add the following attributes with expected values in your Cargo.toml file:
```toml
    [package]
    name = "<UNIQUE_NAME_FOR_YOUR_LIBRARY>"
    version = "<Your semantic versioning>"
    authors = ["<AUTHOR_NAME"]
    description = "<Your Project Description>"
    license = "MIT OR Apache-2.0"
    homepage = "<https://github.com/sampleuser/rustlibrary1>"
    repository = "<https://github.com/sampleuser/rustlibrary1>"
    edition = "2021"
```
* Commit the changes to local git repository (this requires a working git environment).
* Now the library can be published to git with the help of the command below.
    > cargo publish 

### Usage of published library in other projects
To use the published library into other Rust projects, the library needs to be added in the dependencies section of `Cargo.toml` file, as mentioned below
```toml
    [dependencies]
	<UNIQUE_NAME_FOR_YOUR_LIBRARY> = "<your semantic version>"
```