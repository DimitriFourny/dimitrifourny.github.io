#!/usr/bin/env python3
"""Render the article schematics as self-contained SVGs using the site palette."""

from html import escape
from pathlib import Path


IMAGES = Path(__file__).resolve().parents[1] / "_hugo/static/img"
PAPER = "#0a1810"
INK = "#eff9f2"
MUTED = "#b3c8bb"
LINE = "#294334"
ACCENT = "#68efb2"
RAW = "#79c0ff"
DANGER = "#ff9b8d"


class Diagram:
    def __init__(self, width, height, title, description):
        self.width, self.height = width, height
        self.items = [
            f'<title id="title">{escape(title)}</title>',
            f'<desc id="description">{escape(description)}</desc>',
            '<defs>',
            '<style>text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
            f'fill:{INK};font-size:23px}}'
            '.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}'
            '</style>',
        ]
        for name, color in (("ref", ACCENT), ("raw", RAW), ("danger", DANGER)):
            self.items.append(
                f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" '
                'markerWidth="9" markerHeight="9" orient="auto-start-reverse">'
                f'<path d="M 0 1 L 9 5 L 0 9 Z" fill="{color}"/></marker>'
            )
        self.items += ['</defs>', f'<rect width="{width}" height="{height}" fill="{PAPER}"/>']

    def text(self, x, y, value, *, size=23, color=INK, weight=400, anchor="middle", mono=False,
             emphasis=None):
        css_class = ' class="mono"' if mono else ''
        content = escape(value)
        if emphasis:
            before, word, after = value.partition(emphasis)
            if word:
                content = (escape(before) + f'<tspan font-weight="600">{escape(word)}</tspan>'
                           + escape(after))
        self.items.append(
            f'<text x="{x}" y="{y}" text-anchor="{anchor}" dominant-baseline="middle"'
            f'{css_class} style="font-size:{size}px;fill:{color};font-weight:{weight}">'
            f'{content}</text>'
        )

    def path(self, data, kind="ref", *, dashed=False, arrow=True):
        color = {"ref": ACCENT, "raw": RAW, "danger": DANGER}[kind]
        dash = ' stroke-dasharray="8 6"' if dashed else ''
        marker = f' marker-end="url(#{kind})"' if arrow else ''
        self.items.append(
            f'<path d="{data}" fill="none" stroke="{color}" stroke-width="2"'
            f' stroke-linejoin="round"{dash}{marker}/>'
        )

    def box(self, x, y, width, rows, *, row_height=60, timeline=False, danger_row=None, size=23,
            title_weight=600):
        height = row_height * len(rows)
        fill, stroke = ("#18281c", "#88ae7a") if timeline else ("#10281d", "#518564")
        self.items.append(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        for index, label in enumerate(rows):
            if index:
                self.items.append(
                    f'<path d="M {x} {y + index * row_height} H {x + width}" '
                    f'stroke="{stroke}" stroke-opacity=".6"/>'
                )
            if index == danger_row:
                self.items.append(
                    f'<rect x="{x + 1}" y="{y + index * row_height + 1}" '
                    f'width="{width - 2}" height="{row_height - 2}" fill="#3b2020"/>'
                )
            self.text(x + width / 2, y + (index + .5) * row_height, label,
                      size=size, weight=600 if index == danger_row else title_weight if index == 0 else 400,
                      color=DANGER if index == danger_row else INK)

    def js(self, x, y):
        self.items.append(
            f'<ellipse cx="{x}" cy="{y}" rx="92" ry="64" '
            f'fill="#163c2a" stroke="{ACCENT}" stroke-width="2"/>'
        )
        self.text(x, y, "JavaScript", size=24, weight=500)

    def legend(self, y):
        self.path(f"M 64 {y} H 102", arrow=False)
        self.text(118, y, "Retained reference", size=18, color=MUTED, anchor="start")
        self.path(f"M 395 {y} H 433", "raw", arrow=False)
        self.text(449, y, "Raw pointer / linked list", size=18, color=MUTED, anchor="start")
        self.text(965, y, "refcnt = 0: freed object", size=18, color=DANGER)

    def save(self, name):
        source = (
            '<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{self.width}" height="{self.height}" viewBox="0 0 {self.width} {self.height}" '
            'role="img" aria-labelledby="title description">\n'
            + '\n'.join(self.items) + '\n</svg>\n'
        )
        (IMAGES / f"{name}.svg").write_text(source)


def animation_rows(name, count):
    return [name, f"refcnt = {count}", "Animation* mNext", "RefPtr<AnimationTimeline> mTimeline"]


def timeline_rows(count):
    return ["AnimationTimeline", f"refcnt = {count}",
            "Array<RefPtr<Animation>> mAnimations", "LinkedList<Animation> mAnimationOrder"]


def firefox_references():
    d = Diagram(1344, 924, "Animation references without use-after-free",
                "JavaScript retains Animation 1 and Animation 2. Both animations have reference "
                "count 2 and retain the timeline, whose reference count is 2. The timeline tracks "
                "its animations in mAnimations and mAnimationOrder; mNext is a raw pointer.")
    d.js(472, 88)
    for y, text in zip((44, 76, 108, 140), (
        "timeline   = new DocumentTimeline();",
        "animation1 = new Animation(null, timeline);",
        "animation2 = new Animation(null, timeline);",
        "timeline   = null;",
    )):
        d.text(598, y, text, size=22, anchor="start", mono=True)
    d.path("M 472 152 V 176 Q 472 196 452 196 H 362 Q 342 196 342 216 V 238")
    d.path("M 472 152 V 176 Q 472 196 492 196 H 982 Q 1002 196 1002 216 V 238")
    d.path("M 602 392 H 680 Q 702 392 702 370 V 294 Q 702 272 724 272 H 742", "raw")
    d.path("M 342 482 V 544 Q 342 564 362 564 H 652 Q 672 564 672 584 V 600")
    d.path("M 1002 482 V 544 Q 1002 564 982 564 H 692 Q 672 564 672 584 V 600")
    d.path("M 412 752 H 62 Q 42 752 42 732 V 294 Q 42 272 64 272 H 82")
    d.path("M 412 812 H 42 Q 22 812 22 792 V 294 Q 22 272 44 272 H 82", "raw")
    d.path("M 932 812 H 1300 Q 1322 812 1322 790 V 294 Q 1322 272 1300 272 H 1262", "raw")
    d.box(82, 242, 520, animation_rows("Animation 1", 2))
    d.box(742, 242, 520, animation_rows("Animation 2", 2))
    d.box(412, 602, 520, timeline_rows(2), timeline=True)
    d.legend(890)
    d.save("no_uaf")


def firefox_timeline_uaf():
    d = Diagram(1344, 964, "DocumentTimeline use-after-free",
                "JavaScript clears both animation timeline references. The animations still "
                "have reference count 2, but AnimationTimeline reaches reference count 0. "
                "RemoveAnimation is reached through the freed timeline's VTable.")
    d.js(472, 88)
    d.text(598, 66, "animation1.timeline = null;", size=23, anchor="start", mono=True)
    d.text(598, 104, "animation2.timeline = null;", size=23, anchor="start", mono=True)
    d.path("M 472 152 V 176 Q 472 196 452 196 H 362 Q 342 196 342 216 V 238")
    d.path("M 472 152 V 176 Q 472 196 492 196 H 982 Q 1002 196 1002 216 V 238")
    d.path("M 602 392 H 680 Q 702 392 702 370 V 294 Q 702 272 724 272 H 742", "raw")
    d.path("M 412 822 H 62 Q 42 822 42 802 V 294 Q 42 272 64 272 H 82")
    d.path("M 412 882 H 42 Q 22 882 22 862 V 294 Q 22 272 44 272 H 82", "raw")
    d.path("M 932 882 H 1300 Q 1322 882 1322 860 V 294 Q 1322 272 1300 272 H 1262", "raw")
    d.path("M 932 762 H 974", "danger")
    d.box(82, 242, 520, animation_rows("Animation 1", 2))
    d.box(742, 242, 520, animation_rows("Animation 2", 2))
    rows = timeline_rows(0)
    rows.insert(2, "VTable")
    d.box(412, 612, 520, rows, timeline=True, danger_row=1)
    d.box(978, 732, 300, ["RemoveAnimation"], size=23)
    d.legend(940)
    d.save("uaf_timeline")


def firefox_animation_uaf():
    d = Diagram(1344, 1040, "Animation use-after-free",
                "JavaScript clears animation1.timeline and animation1. Animation 1 reaches "
                "reference count 0, while Animation 2 has reference count 2 and the timeline "
                "has reference count 1. animationsToRemove retains a raw pointer to the freed "
                "Animation 1 and a raw pointer to Animation 2.")
    d.js(1012, 88)
    d.text(460, 65, "animation1.timeline = null;", size=23, anchor="middle", mono=True)
    d.text(460, 104, "animation1 = null;", size=23, anchor="middle", mono=True)
    d.box(352, 186, 520, ["Array<Animation*> animationsToRemove"], size=23)
    d.path("M 612 246 V 284 Q 612 306 590 306 H 276 Q 254 306 254 328 V 376", "raw")
    d.path("M 612 246 V 284 Q 612 306 634 306 H 990 Q 1012 306 1012 328 V 376", "raw")
    d.path("M 1012 152 V 376")
    d.path("M 1012 622 V 664 Q 1012 686 990 686 H 690 Q 668 686 668 708 V 746")
    d.path("M 928 898 H 1260 Q 1282 898 1282 876 V 420 Q 1282 400 1262 400 H 1258")
    d.path("M 928 958 H 1290 Q 1312 958 1312 936 V 420 Q 1312 400 1292 400 H 1258", "raw")
    d.box(32, 382, 520, animation_rows("Animation 1", 0), danger_row=1)
    d.box(738, 382, 520, animation_rows("Animation 2", 2))
    d.box(408, 748, 520, timeline_rows(1), timeline=True)
    d.legend(1012)
    d.save("uaf_animation")


def exception_trace():
    d = Diagram(1120, 562, "Windows exception dispatch path",
                "KiDispatchException in ring0 passes the exception to KiUserExceptionDispatcher "
                "in ring3, then RtlDispatchException. The vectored exception path calls "
                "RtlCallVectoredHandlers and RtlpCallVectoredHandlers with RtlpVectoredExceptionList. "
                "The continue path calls RtlCallVectoredContinueHandlers and RtlpCallVectoredHandlers "
                "with RtlpVectoredContinueList.")
    d.path("M 370 62 H 330 Q 308 62 308 84 V 150 Q 308 170 330 170 H 368")
    d.path("M 370 170 H 330 Q 308 170 308 192 V 246 Q 308 266 330 266 H 368")
    d.path("M 496 296 V 320 Q 496 342 474 342 H 310 Q 288 342 288 362 V 366")
    d.path("M 624 296 V 320 Q 624 342 646 342 H 810 Q 832 342 832 362 V 366")
    d.path("M 288 428 V 470")
    d.path("M 832 428 V 470")
    d.box(370, 32, 380, ["KiDispatchException"], size=23, title_weight=400)
    d.items.append(f'<path d="M 278 114 H 940" stroke="{LINE}" stroke-width="2"/>')
    d.text(958, 99, "ring0", size=18, color=MUTED, anchor="start", mono=True)
    d.text(958, 136, "ring3", size=18, color=ACCENT, anchor="start", mono=True)
    d.box(370, 140, 380, ["KiUserExceptionDispatcher"], size=23, title_weight=400)
    d.box(370, 236, 380, ["RtlDispatchException"], size=23, title_weight=400)
    d.box(48, 370, 480, ["RtlCallVectoredHandlers"], size=22, title_weight=400)
    d.box(592, 370, 480, ["RtlCallVectoredContinueHandlers"], size=22, title_weight=400)
    for x, label, emphasis in ((48, "&RtlpVectoredExceptionList", "Exception"),
                               (592, "&RtlpVectoredContinueList", "Continue")):
        d.box(x, 474, 480, [""], row_height=70, title_weight=400)
        d.text(x + 240, 494, "RtlpCallVectoredHandlers(", size=20, mono=True)
        d.text(x + 240, 522, label + ")", size=20, mono=True, emphasis=emphasis)
    d.save("exception_trace")


def veh_list():
    d = Diagram(1040, 1058, "Vectored exception handler linked list and pointer decoding",
                "VECTORED_HANDLER_LIST contains mutexes and first/last pointers for the exception "
                "and continue lists. Each VECTORED_HANDLER_ENTRY contains next, previous, refs, and "
                "an encoded handler pointer. RtlDecodePointer / RtlEncodePointer use XOR and SHIFT "
                "with the process_cookie obtained by NtQueryInformationProcess to recover the handler.")
    # Draw the same first/last entry and pointer-decoding relationships as the original.
    d.path("M 192 158 H 36 Q 14 158 14 180 V 528 Q 14 550 36 550 H 44")
    d.path("M 848 206 H 1004 Q 1026 206 1026 228 V 528 Q 1026 550 1004 550 H 996")
    d.path("M 566 550 H 476", "raw", dashed=True)
    d.path("M 476 706 H 492 Q 514 706 514 728 V 784 Q 514 806 536 806 H 706")
    d.path("M 530 832 H 706")
    d.path("M 880 810 H 950 Q 974 810 974 834 V 976 Q 974 998 952 998 H 846")
    d.box(192, 36, 656, [
        "VECTORED_HANDLER_LIST",
        "void* mutex_exception",
        "VECTORED_HANDLER_ENTRY* first_exception_handler",
        "VECTORED_HANDLER_ENTRY* last_exception_handler",
        "void* mutex_continue",
        "VECTORED_HANDLER_ENTRY* first_continue_handler",
        "VECTORED_HANDLER_ENTRY* last_continue_handler",
    ], row_height=48, size=20, timeline=True)
    rows = ["VECTORED_HANDLER_ENTRY", "VECTORED_HANDLER_ENTRY* next",
            "VECTORED_HANDLER_ENTRY* previous", "ULONG refs",
            "PVECTORED_EXCEPTION_HANDLER handler"]
    d.box(44, 474, 432, rows, row_height=52, size=19)
    d.box(566, 474, 432, rows, row_height=52, size=19)
    d.box(40, 808, 490, ["NtQueryInformationProcess() ⇒ process_cookie"], row_height=48, size=20,
          timeline=True)
    d.items.append(f'<path d="M 708 748 L 878 810 L 708 872 Z" '
                   f'fill="#112b24" stroke="{RAW}" stroke-width="2"/>')
    d.text(779, 810, "XOR + SHIFT", size=18)
    d.text(792, 899, "RtlDecodePointer", size=18, color=MUTED)
    d.text(792, 923, "RtlEncodePointer", size=18, color=MUTED)
    d.items.append(f'<rect x="174" y="954" width="672" height="88" rx="12" '
                   f'fill="#102219" stroke="{LINE}" stroke-width="2"/>')
    d.text(192, 974, "LONG NTAPI VEHHandler(PEXCEPTION_POINTERS ExceptionInfo) {", size=17,
           anchor="start", mono=True)
    d.text(212, 999, "return EXCEPTION_CONTINUE_SEARCH;", size=17, color=ACCENT,
           anchor="start", mono=True)
    d.text(192, 1024, "}", size=17, anchor="start", mono=True)
    d.save("veh")


if __name__ == "__main__":
    for render in (firefox_references, firefox_timeline_uaf, firefox_animation_uaf,
                   exception_trace, veh_list):
        render()
    print("Generated five article diagrams in _hugo/static/img/.")
