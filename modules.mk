mod_wodan.la: mod_wodan.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_wodan.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_wodan.la
