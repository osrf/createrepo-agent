option(CREATEREPO_AGENT_INSTALL_MANPAGES "Install manual pages for createrepo-agent." ON)
if(CREATEREPO_AGENT_INSTALL_MANPAGES)
  install(FILES ${PROJECT_NAME}.1
    DESTINATION share/man/man1
    COMPONENT bin)
endif()
