use anyhow::Result;
use vergen::*;
use pkg_config::find_library;

fn main() -> Result<()> {

    if let Err(e) = find_library("liblzma") {
        panic!("You need to install liblzma-dev. Run \"apt install liblzma-dev\"\n\n{}", e);
	}

    let mut config = Config::default();
    *config.git_mut().sha_kind_mut() = ShaKind::Short;
    *config.build_mut().timestamp_mut() = true;
    *config.git_mut().commit_timestamp_mut() = true;
    vergen(config)
}