ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  # danieltrick/rust-tss2-docker:r36
  export IMAGE_VERSION_RSTSS := 834b8c4436f1fd51a1a7e81834ca598b1dbab959158dbb988ac07509902a9b51
else ifeq ($(RSTSS_BRANCH),nightly)
  # danieltrick/rust-tss2-docker:nightly-r1
  export IMAGE_VERSION_RSTSS := 37d04eda3d7d9fe691a829ea562551b34816726e3a90e4303dc57c57a78ba84b
else ifeq ($(RSTSS_BRANCH),snapshot)
  # danieltrick/rust-tss2-docker:snapshot-r7
  export IMAGE_VERSION_RSTSS := adf4e259bbe028be3a450564058e9d07c7fcd76832dce79e11ec14cfb757c2f9
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
