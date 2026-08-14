ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := sha256:b9b15411399043381ffd6ed787d0085c6dfc9145bde69889bd6c5733a434a7e0
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := sha256:ab8ae391b5a8c4e7641080a6e605c1156f0bc5346f528febdb978ffb5e12dfcc
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := sha256:06facd0a098b95dccc797a183bb553879c8d139ed17b86b8213ce3218e528d81
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
