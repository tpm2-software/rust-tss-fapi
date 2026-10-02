ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  # danieltrick/rust-tss2-docker:r35
  export IMAGE_VERSION_RSTSS := 3f520a878a27b7deb0f7b1f533108ac52db65e0e3f70e400ae8f617d4d749f14
else ifeq ($(RSTSS_BRANCH),nightly)
  # danieltrick/rust-tss2-docker:nightly-r1
  export IMAGE_VERSION_RSTSS := 37d04eda3d7d9fe691a829ea562551b34816726e3a90e4303dc57c57a78ba84b
else ifeq ($(RSTSS_BRANCH),snapshot)
  # danieltrick/rust-tss2-docker:snapshot-r7
  export IMAGE_VERSION_RSTSS := adf4e259bbe028be3a450564058e9d07c7fcd76832dce79e11ec14cfb757c2f9
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
