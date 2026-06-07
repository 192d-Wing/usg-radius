.PHONY: help build release test test-unit test-observability lint fmt \
        image image-push kustomize-build k8s-apply k8s-delete clean

# Image coordinates (override on the CLI: make image IMAGE=reg/usg-radius-server TAG=v0.7.0)
IMAGE    ?= usg-radius-server
TAG      ?= latest
PLATFORMS ?= linux/amd64,linux/arm64
OVERLAY  ?= deploy/overlays/k8s

help:
	@echo "USG RADIUS - Available targets:"
	@echo ""
	@echo "  Building (Rust):"
	@echo "    build              - Debug build"
	@echo "    release            - Release build"
	@echo ""
	@echo "  Testing:"
	@echo "    test               - Run all unit tests (cargo test --workspace)"
	@echo "    test-observability - Run tests including the health/metrics endpoints"
	@echo "    lint / fmt         - clippy / rustfmt"
	@echo ""
	@echo "  Container image (multi-arch, Iron Bank Alpine base):"
	@echo "    image              - buildx build $(IMAGE):$(TAG) for $(PLATFORMS) (load)"
	@echo "    image-push         - buildx build + push $(IMAGE):$(TAG) for $(PLATFORMS)"
	@echo ""
	@echo "  Kubernetes (k3s/k8s + Cilium):"
	@echo "    kustomize-build    - Render manifests for OVERLAY=$(OVERLAY)"
	@echo "    k8s-apply          - kubectl apply -k $(OVERLAY)"
	@echo "    k8s-delete         - kubectl delete -k $(OVERLAY)"
	@echo ""
	@echo "    clean              - cargo clean"

# --- Rust ---
build:
	cargo build

release:
	cargo build --release

test: test-unit

test-unit:
	cargo test --workspace

# Health/metrics endpoints live behind the `observability` feature.
test-observability:
	cargo test -p radius-server --features observability

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

# --- Container image ---
# Multi-arch builds require `docker buildx` and (for Iron Bank base images)
# `docker login registry1.dso.mil`.
image:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) --load .

image-push:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) --push .

# --- Kubernetes ---
kustomize-build:
	kubectl kustomize $(OVERLAY)

k8s-apply:
	kubectl apply -k $(OVERLAY)

k8s-delete:
	kubectl delete -k $(OVERLAY)

clean:
	cargo clean
