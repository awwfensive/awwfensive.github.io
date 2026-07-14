---
title: "Escaping the Recipe Book: Path Traversal in Flyto's `run_recipe`"
date: 2026-07-14
slug: "escaping-the-recipe-book-path-traversal-in-flytos-run-recipe"
description: "How a missing path validation check allows MCP callers to execute arbitrary YAML workflows outside Flyto's intended recipe directory"
tags: ["path traversal", "vulnerability research", "MCP", "filesystem security"]
banner: "/flyto/0.jpeg"
---
## What is flyto-core? 
[Flyto Core](https://github.com/flytohub/flyto-core) is the core execution engine of the Flyto platform that runs automation workflows by orchestrating modules, managing execution state, handling variables and secrets, and recording evidence throughout the workflow lifecycle.

{{< figure src="/flyto/1.png" alt="repo" class="clickable-img" >}}


## What are Flyto recipes?

Flyto supports reusable, pre-built YAML workflows called recipes. They are intended to live in the bundled `src/recipes/` directory, be listed through `list_recipes()`, and be executed by name through the CLI or MCP `run_recipe` tool.

That boundary is not enforced.

A user-controlled recipe name is interpolated directly into a filesystem path. As a result, an MCP caller can use `../` path segments to load and execute a YAML workflow located outside the bundled recipes directory.

Recipes are multi-step YAML workflows that compose Flyto modules. A recipe may launch a browser, navigate to a page, extract data, write a file, or invoke other available modules.

The intended model is straightforward:

- Flyto bundles approved recipes in `src/recipes/`
- `list_recipes()` exposes those available recipes
- A caller provides one of those recipe names to `run_recipe`

This makes the recipe directory an important trust boundary. The MCP tool is described as running a pre-built recipe "by name," not as accepting an arbitrary path to a workflow file.

## The vulnerable code

In `src/cli/recipe.py`, `load_recipe()` constructs a path from the caller-supplied recipe name:

{{< figure src="/flyto/3.png" alt="repo" class="clickable-img" >}}

There is no validation of `recipe_name`, and the resulting path is not resolved and checked to ensure it remains under `RECIPES_DIR`.

Python's `pathlib` does not prevent traversal simply because paths are joined with `/`. If `recipe_name` contains `../`, the filesystem resolves it normally.

For example:

``` bash
src/recipes/ + ../../traversal-poc.yaml
```

can resolve outside the intended recipe directory.

## Reaching it through MCP

The issue is reachable through Flyto's MCP handler:

{{< figure src="/flyto/2.png" alt="repo" class="clickable-img" >}}

An MCP caller controls `recipe_name`, so it can provide traversal sequences directly. The normal listing path does not help here: `list_recipes()` only enumerates `src/recipes/*.yaml`, but `run_recipe()` accepts names that were never listed.

That creates a mismatch between the advertised interface and the effective one:

| Intended behavior | Actual behavior |
|-------------------|-----------------|
| Execute a bundled recipe by name | Load any reachable YAML workflow path ending in `.yaml` |
| `list_recipes()` defines available workflows | Callers can reference workflows that are never listed |
| Recipes are constrained to `src/recipes/` | `../` can escape that directory |

## Proof of concept

A harmless YAML workflow outside `src/recipes/` is sufficient to demonstrate the issue:

```yaml
name: Traversal POC
description: Harmless proof that run_recipe can load outside src/recipes
steps: []
```

Calling:

```python
load_recipe("../../traversal-poc")
```

causes Flyto to resolve and load `traversal-poc.yaml` outside the recipe bundle.

The same behavior is reachable through the MCP-facing execution path:

```python
result = await run_recipe("../../traversal-poc", args={})
```

Instead of returning "Recipe not found," Flyto loads and executes the external workflow.

### POC Validation
From repo root, create a harmless workflow outside src/recipes:
``` bash
cat > traversal-poc.yaml <<'YAML'
name: Traversal POC
description: Harmless proof that run_recipe can load outside src/recipes
steps: []
YAML
```
Confirm `load_recipe()` can escape the recipe directory:
```bash
python -c 'from cli.recipe import load_recipe; print(load_recipe("../../traversal-poc"))'
```
{{< figure src="/flyto/4.png" alt="repo" class="clickable-img" >}}
This confirm's the `load_recipe()` function is considering the attacker input as a name. 

Let's validate through MCP handler because that's the attack surface where the user can supply name via prompt. 
{{< figure src="/flyto/5.png" alt="repo" class="clickable-img" >}}


## Why this matters

This is not automatically remote code execution. Flyto's module policy may block dangerous modules such as shell execution, and the eventual impact depends on the modules permitted in the deployment.

However, the vulnerability bypasses a meaningful workflow-integrity boundary. An MCP caller can run YAML workflows that maintainers did not bundle, review, expose through `list_recipes()`, or intend to make available.

Depending on the allowed module set and filesystem layout, an attacker-controlled or otherwise reachable YAML file could invoke permitted capabilities such as:

- Browser automation
- HTTP requests and other network access
- File operations
- Data transformation and extraction
- Any other module accepted by Flyto's runtime policy

The key issue is not that every external YAML file is necessarily dangerous. It is that `run_recipe` claims to execute a curated built-in recipe while actually accepting a filesystem traversal primitive.

## Fixing the boundary
{{< figure src="/flyto/6.png" alt="repo" class="clickable-img" >}}

The proposed patch resolves both the trusted recipes directory and the caller-derived recipe path before opening the file. Resolving matters because it asks the filesystem for the final location: `..` segments are collapsed and symlinks are followed before the security decision is made.

For a normal bundled recipe such as `daily_report`, the resolved path remains beneath `RECIPES_DIR`:

```text
RECIPES_DIR:                       /app/src/recipes
recipe_name:                       daily_report
resolved recipe path:              /app/src/recipes/daily_report.yaml
```

For a traversal attempt, the same resolution exposes that the final path has escaped the trusted directory:

```text
RECIPES_DIR:                       /app/src/recipes
recipe_name:                       ../../traversal-poc
resolved recipe path:              /app/traversal-poc.yaml
```

The proposed containment check rejects that second path because `/app/src/recipes` is not one of its parent directories.

In other words, this proposed fix uses a final-path check rather than a string check. A caller may supply an unusual path string, but `load_recipe()` would only proceed when the filesystem-resolved target remains inside the bundled recipe tree. This also covers paths that escape through a symlink.

The regression tests should cover a valid bundled recipe, `../` traversal, absolute paths, and a symlink that points outside `RECIPES_DIR`.

## Disclosure Timeline

| Date | Event |
| --- | --- |
| Before v2.26.8 | `run_recipe` accepted a caller-controlled recipe name without proving that the resolved YAML path remained beneath `RECIPES_DIR`. |
| 14 Jul 2026 | This report documented the traversal condition, its MCP reachability, and the proposed resolved-path containment check. |
| v2.26.6 → v2.26.8 | The [upstream comparison](https://github.com/flytohub/flyto-core/compare/v2.26.6...v2.26.8) records the code changes between the affected baseline and the release containing the remediation. |
| CVE pending | The issue is tracked as [GHSA-mxcc-cr6x-2mvr](https://github.com/flytohub/flyto-core/security/advisories/GHSA-mxcc-cr6x-2mvr). A CVE identifier has not yet been assigned. |

## References

- [GitHub Security Advisory: GHSA-mxcc-cr6x-2mvr — CVE pending](https://github.com/flytohub/flyto-core/security/advisories/GHSA-mxcc-cr6x-2mvr)
- [flyto-core comparison: v2.26.6 to v2.26.8](https://github.com/flytohub/flyto-core/compare/v2.26.6...v2.26.8)
