fn main() -> std::io::Result<()> {
    // 使用 vendored protoc，无需系统安装 protobuf-compiler
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"),
    );
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/vnet.proto"], &["proto/"])?;
    Ok(())
}
