'use client';

import React, { useEffect, useState } from 'react';
import { motion, useMotionTemplate } from 'motion/react';
import { Canvas } from '@react-three/fiber';
import { Stars } from '@react-three/drei';
import { FiArrowRight } from 'react-icons/fi';
import { useAuroraColor } from '@/context/AuroraColorContext';

export interface AuroraHeroProps {
  badgeText?: string;
  title?: string | React.ReactNode;
  description?: string | React.ReactNode;
  ctaText?: string;
  onCtaClick?: () => void;
  ctaHref?: string;
}

export function AuroraHero({
  badgeText = 'Beta Now Live!',
  title = (
    <>
      Decrease your SaaS churn by over <span className="text-white">90%</span>
    </>
  ),
  description = 'Lorem ipsum, dolor sit amet consectetur adipisicing elit. Quae, et possimus inventore iste quo veritatis corrupti eligendi.',
  ctaText = 'Start free trial',
  onCtaClick,
  ctaHref,
}: AuroraHeroProps) {
  const [mounted, setMounted] = useState(false);
  const color = useAuroraColor();

  useEffect(() => {
    setMounted(true);
  }, []);

  const backgroundImage = useMotionTemplate`radial-gradient(125% 125% at 50% 0%, #020617 50%, ${color})`;
  const border = useMotionTemplate`1px solid ${color}`;
  const boxShadow = useMotionTemplate`0px 4px 24px ${color}`;

  const ButtonContent = (
    <motion.button
      style={{
        border,
        boxShadow,
      }}
      whileHover={{
        scale: 1.015,
      }}
      whileTap={{
        scale: 0.985,
      }}
      onClick={onCtaClick}
      className="group relative flex w-fit items-center gap-2 rounded-full bg-gray-950/80 px-6 py-3.5 text-sm font-semibold text-gray-50 transition-colors duration-200 hover:bg-gray-900 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-white/40"
    >
      <span>{ctaText}</span>
      <FiArrowRight className="text-base transition-transform duration-200 group-hover:-rotate-45 group-active:-rotate-12" />
    </motion.button>
  );

  return (
    <motion.section
      style={{
        backgroundImage,
      }}
      className="relative min-h-screen overflow-hidden bg-gray-950 px-4 py-24 text-gray-200 grid place-content-center"
    >
      {/* 3D Starfield Background Canvas */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        {mounted && (
          <Canvas>
            <Stars radius={50} count={2500} factor={4} fade speed={2} />
          </Canvas>
        )}
      </div>

      {/* Foreground Content */}
      <div className="relative z-10 flex flex-col items-center text-center max-w-5xl mx-auto">
        {/* Top Badge */}
        <span className="mb-4 inline-flex items-center gap-1.5 rounded-full bg-gray-600/50 px-3.5 py-1.5 text-xs font-medium text-gray-200 border border-white/10 backdrop-blur-md shadow-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          {badgeText}
        </span>

        {/* Hero Heading */}
        <h1 className="max-w-4xl bg-gradient-to-br from-white to-gray-400 bg-clip-text text-center text-3xl font-bold tracking-tight text-transparent sm:text-5xl md:text-7xl leading-[1.15]">
          {title}
        </h1>

        {/* Hero Body Description */}
        <p className="my-6 max-w-xl text-center text-base sm:text-lg leading-relaxed text-gray-400 font-sans">
          {description}
        </p>

        {/* Dynamic Glowing CTA Button */}
        {ctaHref ? (
          <a href={ctaHref} className="inline-block">
            {ButtonContent}
          </a>
        ) : (
          ButtonContent
        )}
      </div>
    </motion.section>
  );
}

export default AuroraHero;
