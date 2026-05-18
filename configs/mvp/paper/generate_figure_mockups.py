#!/usr/bin/env python3
"""Generate bitmap mockups from figure_drawing_guide.md via Right Code.

The generated images are intended as layout references for manually redrawing
editable vector figures. They are not final paper assets.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MODEL = "gpt-image-2-vip"
DEFAULT_ENDPOINT = "https://www.right.codes/draw/v1/images/generations"
DEFAULT_GUIDE = Path(__file__).with_name("figure_drawing_guide.md")
DEFAULT_OUTPUT_DIR = Path(__file__).with_name("generated_figure_mockups")
STYLE_LOCK_HEADING = "## EMNLP Figure Style Lock"
DEFAULT_APPENDIX_SLUGS = {"appendix_a7_b3_internal_authority_case"}
COMPACT_STYLE_LOCK = """Create a restrained EMNLP/ACL-style academic vector figure.
White background, flat shapes, thin gray strokes, no gradients, shadows, 3D, logos, or decorative effects.
Use a consistent palette: blue for live execution/main benchmark, teal for replay, amber for risk/internal authority, red for violations, green for safe/pass/recovered, purple for diagnosis, gray for notes/axes.
Use short labels, generous margins, legible two-column text, simple arrows, compact metric chips, and table/bar elements.
Do not write "defense", "causal proof", "simulator", or "dominant cause"."""


@dataclass(frozen=True)
class FigurePrompt:
    title: str
    slug: str
    target: str | None
    prompt: str
    is_appendix: bool


class ImageRequestError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body or ""


def slugify(title: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", title.strip().lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned or "figure"


def read_fenced_block(lines: list[str], start_index: int) -> tuple[str, int]:
    """Read a fenced code block after start_index.

    start_index should point at the line after the "GPT-Image sample prompt:"
    marker. Returns (block_text, next_index_after_block).
    """
    i = start_index
    while i < len(lines) and not lines[i].strip().startswith("```"):
        i += 1
    if i >= len(lines):
        raise ValueError("Missing opening fenced block for GPT-Image prompt")

    i += 1
    block: list[str] = []
    while i < len(lines) and not lines[i].strip().startswith("```"):
        block.append(lines[i].rstrip("\n"))
        i += 1
    if i >= len(lines):
        raise ValueError("Missing closing fenced block for GPT-Image prompt")
    return "\n".join(block).strip(), i + 1


def parse_figure_prompts(guide_path: Path) -> list[FigurePrompt]:
    lines = guide_path.read_text(encoding="utf-8").splitlines(keepends=True)
    prompts: list[FigurePrompt] = []

    current_title: str | None = None
    current_slug: str | None = None
    current_target: str | None = None
    current_is_appendix = False
    waiting_for_target = False

    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        heading = re.match(r"^(##|###)\s+(.+?)\s*$", stripped)
        if heading:
            level, title = heading.groups()
            if title.startswith("Figure ") or title.startswith("Appendix "):
                current_title = title
                current_slug = slugify(title)
                current_target = None
                current_is_appendix = level == "###" or title.startswith("Appendix ")
            waiting_for_target = False
            i += 1
            continue

        if current_title and stripped in {"Target file:", "Target:"}:
            waiting_for_target = True
            i += 1
            continue

        if waiting_for_target and stripped.startswith("```"):
            target, next_i = read_fenced_block(lines, i)
            current_target = target.splitlines()[0].strip() if target else None
            waiting_for_target = False
            i = next_i
            continue

        if current_title and stripped == "GPT-Image sample prompt:":
            prompt, next_i = read_fenced_block(lines, i + 1)
            prompts.append(
                FigurePrompt(
                    title=current_title,
                    slug=current_slug or slugify(current_title),
                    target=current_target,
                    prompt=prompt,
                    is_appendix=current_is_appendix,
                )
            )
            i = next_i
            continue

        i += 1

    return prompts


def parse_style_lock(guide_path: Path) -> str:
    lines = guide_path.read_text(encoding="utf-8").splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip() == STYLE_LOCK_HEADING:
            block, _ = read_fenced_block(lines, i + 1)
            return block
    return ""


def select_prompts(
    prompts: list[FigurePrompt],
    include_appendix: bool,
    all_appendix: bool,
    only: set[str] | None,
    skip: set[str] | None,
    missing_only: bool,
    output_dir: Path,
) -> list[FigurePrompt]:
    selected: list[FigurePrompt] = []
    for item in prompts:
        if item.is_appendix and not include_appendix:
            continue
        if item.is_appendix and include_appendix and not all_appendix and item.slug not in DEFAULT_APPENDIX_SLUGS:
            continue
        aliases = {item.slug, item.title.lower()}
        if item.target:
            aliases.add(Path(item.target).stem.lower())
        if only and not aliases.intersection(only):
            continue
        if skip and aliases.intersection(skip):
            continue
        if missing_only and (output_dir / f"{item.slug}.png").exists():
            continue
        selected.append(item)
    return selected


def combine_prompt(prompt: str, style_lock: str) -> str:
    if not style_lock:
        return prompt
    return (
        f"{style_lock.strip()}\n\n"
        "Apply the shared style above strictly, then render the specific figure below.\n\n"
        f"{prompt.strip()}"
    )


def build_request_payload(prompt: str, model: str, size: str, quality: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "n": 1,
        "size": size,
    }
    if quality:
        payload["quality"] = quality
    return payload


def decode_image_response(data: dict[str, Any]) -> bytes:
    if not data.get("data"):
        raise ValueError(f"Image response does not contain data: {data}")

    first = data["data"][0]
    b64 = first.get("b64_json")
    if b64:
        return base64.b64decode(b64)

    url = first.get("url")
    if url:
        with urllib.request.urlopen(url, timeout=180) as response:
            return response.read()

    raise ValueError(f"Image response has neither b64_json nor url: {first}")


def is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, ImageRequestError):
        if exc.status_code in {408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524}:
            return True
        body = exc.body.lower()
        return "upstream_error" in body or "system error" in body or "timeout" in body
    text = str(exc).lower()
    return "upstream_error" in text or "system error" in text or "timeout" in text


def write_error_file(path: Path, exc: Exception, attempt: int) -> None:
    detail = {
        "attempt": attempt,
        "error_type": type(exc).__name__,
        "error": str(exc),
    }
    if isinstance(exc, ImageRequestError):
        detail["status_code"] = exc.status_code
        detail["body"] = exc.body
    path.write_text(json.dumps(detail, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate_one(
    item: FigurePrompt,
    *,
    endpoint: str,
    api_key: str,
    model: str,
    size: str,
    quality: str | None,
    output_dir: Path,
    timeout: int,
    overwrite: bool,
    style_lock: str,
    retries: int,
    retry_delay: float,
    retry_backoff: float,
) -> dict[str, Any]:
    output_path = output_dir / f"{item.slug}.png"
    prompt_path = output_dir / f"{item.slug}.prompt.txt"
    response_path = output_dir / f"{item.slug}.response.json"
    error_path = output_dir / f"{item.slug}.error.json"

    if output_path.exists() and not overwrite:
        return {
            "title": item.title,
            "slug": item.slug,
            "target": item.target,
            "output": str(output_path),
            "status": "skipped_exists",
        }

    full_prompt = combine_prompt(item.prompt, style_lock)
    prompt_path.write_text(full_prompt + "\n", encoding="utf-8")
    payload = build_request_payload(full_prompt, model=model, size=size, quality=quality)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    last_exc: Exception | None = None
    max_attempts = retries + 1
    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_body = response.read().decode("utf-8")
            break
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            last_exc = ImageRequestError(
                f"HTTP {exc.code} for {item.title}: {error_body}",
                status_code=exc.code,
                body=error_body,
            )
        except urllib.error.URLError as exc:
            last_exc = ImageRequestError(f"Network error for {item.title}: {exc}", body=str(exc))

        write_error_file(error_path, last_exc, attempt)
        if attempt >= max_attempts or not is_retryable_error(last_exc):
            raise last_exc
        sleep_for = retry_delay * (retry_backoff ** (attempt - 1))
        print(f"  retryable error on attempt {attempt}/{max_attempts}; sleeping {sleep_for:.1f}s", file=sys.stderr)
        time.sleep(sleep_for)
    else:
        raise last_exc or RuntimeError(f"Unknown image generation error for {item.title}")

    data = json.loads(response_body)
    image_bytes = decode_image_response(data)

    output_path.write_bytes(image_bytes)
    response_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if error_path.exists():
        error_path.unlink()

    return {
        "title": item.title,
        "slug": item.slug,
        "target": item.target,
        "output": str(output_path),
        "prompt": str(prompt_path),
        "response": str(response_path),
        "status": "generated",
    }


def normalize_selector(values: list[str] | None) -> set[str] | None:
    if not values:
        return None
    out: set[str] = set()
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            out.add(part.lower())
            out.add(slugify(part))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate GPT-Image mockups for TraceProbe paper figures using Right Code.",
    )
    parser.add_argument("--guide", type=Path, default=DEFAULT_GUIDE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--endpoint", default=os.environ.get("RIGHT_CODE_IMAGE_ENDPOINT", DEFAULT_ENDPOINT))
    parser.add_argument("--model", default=os.environ.get("RIGHT_CODE_IMAGE_MODEL", DEFAULT_MODEL))
    parser.add_argument("--api-key", default=os.environ.get("RIGHT_CODE_API_KEY"))
    parser.add_argument("--size", default="1792x1024", help="Image size passed to the image API.")
    parser.add_argument("--quality", default=None, help="Optional API quality value, if supported by the provider.")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between API calls.")
    parser.add_argument("--retries", type=int, default=2, help="Retry retryable image API failures per figure.")
    parser.add_argument("--retry-delay", type=float, default=15.0, help="Initial seconds before retry.")
    parser.add_argument("--retry-backoff", type=float, default=2.0, help="Retry delay multiplier.")
    parser.add_argument(
        "--include-appendix",
        action="store_true",
        help="Also generate high-priority appendix mockups. Currently this means A7 only.",
    )
    parser.add_argument(
        "--all-appendix",
        action="store_true",
        help="Generate every optional appendix mockup. Most are not referenced by the paper draft.",
    )
    parser.add_argument("--only", nargs="*", help="Generate only selected slugs, titles, or target stems.")
    parser.add_argument("--skip", nargs="*", help="Skip selected slugs, titles, or target stems.")
    parser.add_argument("--missing-only", action="store_true", help="Only generate prompts whose PNG output is missing.")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-style-lock", action="store_true", help="Do not prepend the shared EMNLP style block.")
    parser.add_argument("--compact-style", action="store_true", help="Use a shorter shared style prompt to reduce provider timeouts.")
    parser.add_argument("--list", action="store_true", help="List parsed prompts and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Parse and print selected prompts without API calls.")
    args = parser.parse_args()

    prompts = parse_figure_prompts(args.guide)
    if args.no_style_lock:
        style_lock = ""
    elif args.compact_style:
        style_lock = COMPACT_STYLE_LOCK
    else:
        style_lock = parse_style_lock(args.guide)
    only = normalize_selector(args.only)
    skip = normalize_selector(args.skip)
    selected = select_prompts(
        prompts,
        include_appendix=args.include_appendix or args.all_appendix,
        all_appendix=args.all_appendix,
        only=only,
        skip=skip,
        missing_only=args.missing_only,
        output_dir=args.output_dir,
    )

    if args.list or args.dry_run:
        for item in selected:
            kind = "appendix" if item.is_appendix else "main"
            print(f"{item.slug}\t{kind}\t{item.title}\t{item.target or ''}")
        return 0

    if not args.api_key:
        print(
            "Missing API key. Set RIGHT_CODE_API_KEY or pass --api-key. "
            "The script intentionally does not read OPENAI_API_KEY for the third-party Right Code endpoint.",
            file=sys.stderr,
        )
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output_dir / "manifest.jsonl"

    print(f"Guide: {args.guide}")
    print(f"Endpoint: {args.endpoint}")
    print(f"Model: {args.model}")
    print(f"Output: {args.output_dir}")
    print(f"Selected prompts: {len(selected)}")
    print(f"Style lock: {'enabled' if style_lock else 'disabled'}")

    with manifest_path.open("a", encoding="utf-8") as manifest:
        for index, item in enumerate(selected, 1):
            print(f"[{index}/{len(selected)}] {item.title} -> {item.slug}.png")
            try:
                result = generate_one(
                    item,
                    endpoint=args.endpoint,
                    api_key=args.api_key,
                    model=args.model,
                    size=args.size,
                    quality=args.quality,
                    output_dir=args.output_dir,
                    timeout=args.timeout,
                    overwrite=args.overwrite,
                    style_lock=style_lock,
                    retries=args.retries,
                    retry_delay=args.retry_delay,
                    retry_backoff=args.retry_backoff,
                )
            except Exception as exc:  # noqa: BLE001
                result = {
                    "title": item.title,
                    "slug": item.slug,
                    "target": item.target,
                    "status": "error",
                    "error": str(exc),
                }
                print(f"ERROR: {exc}", file=sys.stderr)
            result["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            manifest.write(json.dumps(result, ensure_ascii=False) + "\n")
            manifest.flush()
            print(f"  {result['status']}")
            if index < len(selected) and args.sleep > 0:
                time.sleep(args.sleep)

    print(f"Wrote manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
