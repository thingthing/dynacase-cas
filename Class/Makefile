appname = WHAT
export appname

include $(utildir)/PubRule

classes = $(patsubst %.php,$(pubdir)/$(applib)/%.php,$(wildcard Class*.php))

$(pubdir)/$(applib):
	mkdir -p $@

$(pubdir)/$(applib)/%.php: %.php $(pubdir)/$(applib)
	cp $< $@

publish: $(classes)
