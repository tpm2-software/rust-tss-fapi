ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := sha256:c33d92b8bd58a5397cf6ca7af960a68658256209a3f05c7be89bd55fdf007b45
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := sha256:6e7f3de9c3b0298192a4db108d955cd203b360fd1fb40b5f6940c9e3ecf7cc0b
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := sha256:5e02daff85e7678c6715db7b9c07e96d3117bf04e8ec7eaba4a8958181035017
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
