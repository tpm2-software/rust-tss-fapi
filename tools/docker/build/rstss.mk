ifeq ($(filter-out stable,$(RSTSS_BRANCH)),)
  export IMAGE_VERSION_RSTSS := afc63715c08267a86965d805c2dd8a06c6383c0d06b03f268878b2f40398b489
else ifeq ($(RSTSS_BRANCH),unstable)
  export IMAGE_VERSION_RSTSS := f9bc7b41138a181be8c551f22f3a9228de846b1beeff0610860afaf188ded4fd
else ifeq ($(RSTSS_BRANCH),bleeding-edge)
  export IMAGE_VERSION_RSTSS := e67d5cae11834e61ef1c2495119a8e4b820118d6743cdd26eb31a24c4d09e8b5
else
  $(error Unsupport RSTSS_BRANCH branch "$(RSTSS_BRANCH)" specified!)
endif
