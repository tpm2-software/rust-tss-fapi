ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := 98227fe354f06ef877ebdfaf6f13aa0caffb7f409c20223e160e415c8c524746
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := 494bc8a7ad2d701b30b5788480a624c1f0e691413698136da70933f20aff89cb
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := 1d2135c1620ccab99b16e3f4f46f76e565767b284b59a5574b941ea6c1b4820f
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
