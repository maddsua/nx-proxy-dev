BUILDDIR=.build
VERSION=0.0.0

clean:
	rm -rf $(BUILDDIR) || true

build-deb:
	mkdir -p $(BUILDDIR)
	cp -r packages/debian $(BUILDDIR)
	mkdir -p $(BUILDDIR)/debian/usr/bin
	go build -v -o $(BUILDDIR)/debian/usr/bin/nx-proxy -ldflags "-s -w" ./cmd/
	echo "Version: $(VERSION)" >> $(BUILDDIR)/debian/DEBIAN/control
	chmod +x $(BUILDDIR)/debian/DEBIAN/postinst
	dpkg-deb -v --build --root-owner-group $(BUILDDIR)/debian
	mv $(BUILDDIR)/debian.deb $(BUILDDIR)/nx-proxy-$(VERSION).deb
