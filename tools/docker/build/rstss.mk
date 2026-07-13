ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := sha256:50feada2f78d3393c151b4d49d639ba2c6518b2cadf76c49e5fe8977b89c9fa4
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := sha256:c8464bf6cb191194a226bef0e4d9fea90b6d51ba5b05417e01a3cf2e543c6228
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := sha256:1e51c7bbeefc11c838e796cc2bdc8d69f2a7063893680e88c7a2da9e1ed9fdb7
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
