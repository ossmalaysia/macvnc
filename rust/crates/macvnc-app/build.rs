fn main() {
    println!("cargo:rerun-if-changed=assets/macvnc.ico");
    println!("cargo:rerun-if-changed=Cargo.toml");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/macvnc.ico")
            .set("ProductName", "MacVNC")
            .set("CompanyName", "AnchorSprint")
            .set("FileDescription", "MacVNC High Performance Screen Sharing")
            .set("InternalName", "MacVNC")
            .set("OriginalFilename", "macvnc-app.exe")
            .compile()
            .expect("compile MacVNC icon and version resources");
    }
}
