ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := sha256:276c6d4e9510ede4a2e868e0158e7ae79b99393656f889670da8ce4dc44746e4
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := sha256:c8464bf6cb191194a226bef0e4d9fea90b6d51ba5b05417e01a3cf2e543c6228
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := sha256:58066d0ad1ab47fb4e60e52bfe90ea59f8a5bbb5c6c011e2e3523c2c6b1dfa63
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
