ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  # danieltrick/rust-tss2-docker:r37
  export IMAGE_VERSION_RSTSS := 1dd5e2ee7dcd07b70aad244066860e291a57cc4828b5bdc868b3d51b01d5136a
else ifeq ($(RSTSS_BRANCH),nightly)
  # danieltrick/rust-tss2-docker:nightly-r2
  export IMAGE_VERSION_RSTSS := 1339368571df468a4855842adb8140e18bef91e9f21886268342e1efa8a61765
else ifeq ($(RSTSS_BRANCH),snapshot)
  # danieltrick/rust-tss2-docker:snapshot-r8
  export IMAGE_VERSION_RSTSS := c5c17a6a1ee98c90777a22d9b859b1c40d3fb03dda78840a62013ce74a5be6ea
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
