.PHONY: install format lint typecheck test build java-test java-run dev-api dev-web demo-token

ifneq (,$(wildcard ./.env))
include .env
export
endif

install:
	npm ci

format:
	npm run format --workspaces --if-present

lint:
	npm run lint

typecheck:
	npm run typecheck

test:
	npm run test
	$(MAKE) java-test

build:
	npm run build

java-test:
	$(MAKE) -C services/credential-detector test

java-run:
	$(MAKE) -C services/credential-detector run

dev-api:
	npm run start:dev --workspace @attestguard/api

dev-web:
	npm run dev --workspace @attestguard/web

demo-token:
	node scripts/create-demo-token.mjs
