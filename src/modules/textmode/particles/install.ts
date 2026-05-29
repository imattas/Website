import { effectsConfig, type ParticleContext } from "../../../config";

const particleLayerClass = "ascii-particles";
const config = effectsConfig.particles;

type Particle = {
  element: HTMLSpanElement;
  x: number;
  y: number;
  driftX: number;
  driftY: number;
  opacity: number;
  phase: number;
  speed: number;
  context: ParticleContext;
};

export function installAsciiParticles(): void {
  if (
    !config.enable ||
    typeof window === "undefined" ||
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  ) {
    return;
  }

  if (document.querySelector(`.${particleLayerClass}`)) {
    return;
  }

  const layer = document.createElement("div");
  layer.className = particleLayerClass;
  layer.dataset.particleContext = particleContext();
  layer.setAttribute("aria-hidden", "true");
  document.body.append(layer);

  const particles = createParticles(layer, particleCount());
  const pointer = { x: Number.NaN, y: Number.NaN };
  let animationId = 0;
  let running = true;
  const frame = (time: number) => {
    if (!running) {
      return;
    }

    animateParticles(layer, particles, pointer, time);
    animationId = window.requestAnimationFrame(frame);
  };
  animationId = window.requestAnimationFrame(frame);

  const reset = () => {
    for (const particle of particles) {
      resetParticle(particle, true);
    }
  };

  window.addEventListener("resize", reset, { passive: true });
  window.addEventListener("orientationchange", reset, { passive: true });
  window.addEventListener(
    "pointermove",
    (event) => {
      pointer.x = event.clientX;
      pointer.y = event.clientY;
    },
    { passive: true }
  );
  window.addEventListener(
    "pointerleave",
    () => {
      pointer.x = Number.NaN;
      pointer.y = Number.NaN;
    },
    { passive: true }
  );
  window.addEventListener("beforeunload", () => {
    window.cancelAnimationFrame(animationId);
    animationId = 0;
  });
  document.addEventListener("visibilitychange", () => {
    running = document.visibilityState === "visible";

    if (running && animationId === 0) {
      animationId = window.requestAnimationFrame(frame);
      return;
    }

    if (!running && animationId !== 0) {
      window.cancelAnimationFrame(animationId);
      animationId = 0;
    }
  });
}

function createParticles(layer: HTMLElement, count: number): Particle[] {
  const context = particleContext();

  return Array.from({ length: count }, () => {
    const element = document.createElement("span");
    element.textContent = sample(config.chars);
    layer.append(element);

    const particle: Particle = {
      element,
      x: 0,
      y: 0,
      driftX: 0,
      driftY: 0,
      opacity: 0,
      phase: 0,
      speed: 0,
      context
    };

    resetParticle(particle, true);
    return particle;
  });
}

function animateParticles(
  layer: HTMLElement,
  particles: Particle[],
  pointer: { x: number; y: number },
  time: number
): void {
  if (!document.body.contains(layer)) {
    return;
  }

  for (const particle of particles) {
    particle.x += particle.driftX;
    particle.y += particle.driftY;
    applyPointerInfluence(particle, pointer);
    particle.phase += particle.speed;

    const flicker = 0.72 + Math.sin(time * 0.0017 + particle.phase) * 0.28;
    particle.element.style.opacity = (particle.opacity * flicker).toFixed(3);
    particle.element.style.transform = `translate3d(${particle.x.toFixed(1)}px, ${particle.y.toFixed(1)}px, 0)`;

    if (
      particle.y < -24 ||
      particle.y > window.innerHeight + 24 ||
      particle.x < -24 ||
      particle.x > window.innerWidth + 24
    ) {
      resetParticle(particle, false);
    }
  }
}

function resetParticle(particle: Particle, anywhere: boolean): void {
  const side = randomInt(0, 3);
  const fromEdge = !anywhere && side;
  const width = Math.max(1, window.innerWidth);
  const height = Math.max(1, window.innerHeight);

  particle.x =
    fromEdge === 1
      ? width + randomBetween(4, 20)
      : fromEdge === 2
        ? -randomBetween(4, 20)
        : randomParticleX(width, particle.context);
  particle.y =
    fromEdge === 3 ? height + randomBetween(4, 20) : fromEdge ? randomBetween(0, height) : randomBetween(0, height);
  particle.driftX = randomBetween(...config.driftX);
  particle.driftY = randomBetween(...config.driftY);
  particle.opacity = randomParticleOpacity(particle.context);
  particle.phase = randomBetween(0, Math.PI * 2);
  particle.speed = randomBetween(...config.speed);
  particle.element.textContent = sample(config.chars);
}

function particleCount(): number {
  const mobile = window.matchMedia(`(max-width: ${config.mobileBreakpoint}px)`).matches;
  const context = particleContext();
  const contextConfig = config.contexts[context];

  return mobile ? contextConfig.mobileCount : contextConfig.desktopCount;
}

function particleContext(): ParticleContext {
  if (document.querySelector(".home-shell")) {
    return "home";
  }

  if (document.querySelector(".volume-wrap")) {
    return "volume";
  }

  return "article";
}

function randomParticleX(width: number, context: ParticleContext): number {
  if (context === "home" || width <= config.contentSafeWidth + 120) {
    return randomBetween(0, width);
  }

  const gutter = Math.max(0, (width - config.contentSafeWidth) / 2);
  if (maybe(0.5)) {
    return randomBetween(0, Math.max(1, gutter * 0.82));
  }

  return randomBetween(Math.min(width, width - gutter * 0.82), width);
}

function randomParticleOpacity(context: ParticleContext): number {
  return randomBetween(...config.contexts[context].opacity);
}

function applyPointerInfluence(particle: Particle, pointer: { x: number; y: number }): void {
  if (!Number.isFinite(pointer.x) || !Number.isFinite(pointer.y)) {
    return;
  }

  const dx = particle.x - pointer.x;
  const dy = particle.y - pointer.y;
  const distance = Math.hypot(dx, dy);

  if (distance <= 0 || distance > config.pointerInfluenceRadius) {
    return;
  }

  const force = (1 - distance / config.pointerInfluenceRadius) ** 2;
  const contextScale = config.contexts[particle.context].pointerScale;
  particle.x += (dx / distance) * force * contextScale * 1.8;
  particle.y += (dy / distance) * force * contextScale * 1.2;
  particle.phase += force * contextScale * 0.08;
}

function sample<T>(items: T[]): T {
  return items[randomInt(0, items.length - 1)] ?? items[0];
}

function randomBetween(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

function randomInt(min: number, max: number): number {
  return Math.floor(randomBetween(min, max + 1));
}

function maybe(probability: number): boolean {
  return Math.random() < probability;
}
