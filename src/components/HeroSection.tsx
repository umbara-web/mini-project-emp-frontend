'use client';

import React, { useState } from 'react';
// import { useNavigate, Link } from 'react-router-dom';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useStore } from './Store';
import { EventCard } from './EventCard';
import { EventCategory } from '../types/types';
import { Search, MapPin, ArrowRight } from 'lucide-react';

const CATEGORY_IMAGES: Record<EventCategory, string> = {
  [EventCategory.MUSIC]:
    'https://images.unsplash.com/photo-1470225620780-dba8ba36b745?q=80&w=200&h=200&fit=crop',
  [EventCategory.WORKSHOP]:
    'https://images.unsplash.com/photo-1544531586-fde5298cdd40?q=80&w=200&h=200&fit=crop',
  [EventCategory.CULTURE]:
    'https://images.unsplash.com/photo-1460723237483-7a6dc9d0b212?q=80&w=200&h=200&fit=crop',
  [EventCategory.SPORTS]:
    'https://images.unsplash.com/photo-1461896836934-ffe607ba8211?q=80&w=200&h=200&fit=crop',
  [EventCategory.TECH]:
    'https://images.unsplash.com/photo-1518770660439-4636190af475?q=80&w=200&h=200&fit=crop',
  [EventCategory.TRAVEL]:
    'https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?q=80&w=200&h=200&fit=crop',
};

export default function HeroSection() {
  const { events } = useStore();
  const router = useRouter();
  const [searchTerm, setSearchTerm] = useState('');
  const [location, setLocation] = useState('Mumbai');

  const handleSearch = () => {
    router.push(
      `/events?search=${encodeURIComponent(searchTerm)}&location=${encodeURIComponent(location)}`
    );
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const featuredEvents = events.slice(0, 3);
  const onlineEvents = events
    .filter(
      (e) =>
        e.tags?.includes('Education') || e.category === EventCategory.WORKSHOP
    )
    .slice(0, 3);
  const trendingEvents = events.slice(3, 6);

  return (
    <div className='bg-white'>
      {/* Hero Section */}
      <div className='relative bg-[#2e2532] text-white'>
        {/* Background Image Overlay */}
        <div className='absolute inset-0 z-0'>
          <img
            src='https://images.unsplash.com/photo-1492684223066-81342ee5ff30?q=80&w=2000&auto=format&fit=crop'
            className='h-full w-full object-cover opacity-20 mix-blend-overlay'
            alt='Hero Background'
          />
          <div className='absolute inset-0 bg-linear-to-t from-[#1e1e2e] via-transparent to-transparent'></div>
        </div>

        <div className='relative z-10 container mx-auto px-4 py-20 text-center sm:px-6 lg:px-8 lg:py-32'>
          <p className='mb-2 text-xl font-semibold text-yellow-400 md:text-2xl'>
            Don't miss out!
          </p>
          <h1 className='mb-8 text-4xl font-bold tracking-tight md:text-6xl'>
            Explore the <span className='text-yellow-400'>vibrant events</span>{' '}
            happening locally and globally.
          </h1>

          {/* Search Bar */}
          <div className='mx-auto flex max-w-dvh flex-col items-center gap-2 rounded-lg bg-white p-2 shadow-lg md:flex-row md:gap-0'>
            <div className='flex w-full flex-1 items-center px-4'>
              <Search className='mr-2 h-5 w-5 text-gray-400' />
              <input
                type='text'
                placeholder='Search Events, Categories, Location,...'
                className='w-full py-3 text-gray-700 placeholder-gray-400 focus:outline-none'
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={handleKeyDown}
              />
            </div>
            <div className='mx-2 hidden h-8 w-px bg-gray-200 md:block'></div>
            <div className='flex w-full flex-none items-center border-t border-gray-100 px-4 pt-2 md:w-auto md:border-t-0 md:pt-0'>
              <MapPin className='mr-2 h-5 w-5 text-gray-400' />
              <select
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                className='w-full cursor-pointer bg-transparent py-3 text-gray-700 focus:outline-none md:w-auto'
              >
                <option value='Mumbai'>Mumbai</option>
                <option value='Jakarta'>Jakarta</option>
                <option value='Bali'>Bali</option>
                <option value='Online'>Online</option>
              </select>
            </div>
            <button
              onClick={handleSearch}
              className='w-full rounded-md bg-[#1e1e2e] px-8 py-3 font-bold text-white transition-colors hover:bg-[#2d2d44] md:ml-2 md:w-auto'
            >
              Search
            </button>
          </div>
        </div>
      </div>

      <div className='container mx-auto space-y-16 px-4 py-12 sm:px-6 lg:px-8'>
        {/* Categories */}
        <section>
          <h2 className='mb-8 text-2xl font-bold text-gray-900'>
            Explore Categories
          </h2>
          <div className='grid grid-cols-2 gap-8 md:grid-cols-3 lg:grid-cols-6'>
            {Object.entries(EventCategory).map(([key, label]) => (
              <Link
                href={`/events?category=${label}`}
                key={key}
                className='group flex flex-col items-center'
              >
                <div className='mb-3 h-24 w-24 overflow-hidden rounded-full border-2 border-transparent shadow-md transition-all group-hover:border-yellow-400 group-hover:shadow-lg'>
                  <img
                    src={CATEGORY_IMAGES[label as EventCategory]}
                    alt={label}
                    className='h-full w-full transform object-cover transition-transform duration-300 group-hover:scale-110'
                  />
                </div>
                <span className='text-center text-sm font-medium text-gray-700 group-hover:text-[#1e1e2e]'>
                  {label}
                </span>
              </Link>
            ))}
          </div>
        </section>

        {/* Popular Events */}
        <section>
          <div className='mb-6 flex items-center justify-between'>
            <h2 className='text-2xl font-bold text-gray-900'>
              Popular Events in Mumbai
            </h2>
            <div className='flex space-x-2'>
              <button
                onClick={() => router.push('/events')}
                className='rounded-full border border-gray-300 px-3 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100'
              >
                All
              </button>
              <button
                onClick={() => router.push('/events?date=today')}
                className='rounded-full border border-gray-300 px-3 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100'
              >
                Today
              </button>
              <button
                onClick={() => router.push('/events?date=tomorrow')}
                className='rounded-full border border-gray-300 px-3 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100'
              >
                Tomorrow
              </button>
              <button
                onClick={() => router.push('/events?date=weekend')}
                className='rounded-full border border-gray-300 px-3 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100'
              >
                This Weekend
              </button>
            </div>
          </div>
          <div className='grid grid-cols-1 gap-6 md:grid-cols-3'>
            {featuredEvents.map((event) => (
              <EventCard key={event.id} event={event} />
            ))}
          </div>
          <div className='mt-8 text-center'>
            <Link
              href='/events'
              className='inline-block rounded-md border border-gray-300 px-8 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50'
            >
              See More
            </Link>
          </div>
        </section>

        {/* Discover Online Events */}
        <section className='container mx-auto'>
          <h2 className='mb-6 text-2xl font-bold text-gray-900'>
            Discover Best of Online Events
          </h2>
          <div className='grid grid-cols-1 gap-6 md:grid-cols-3'>
            {onlineEvents.map((event) => (
              <EventCard key={event.id} event={event} />
            ))}
          </div>
        </section>

        {/* Curated Banner */}
        <section className='relative overflow-hidden rounded-2xl bg-yellow-100 p-8 md:p-12'>
          <div className='pointer-events-none absolute top-0 right-0 h-full w-1/2 opacity-10'>
            <svg
              viewBox='0 0 200 200'
              xmlns='http://www.w3.org/2000/svg'
              className='h-full w-full'
            >
              <path
                fill='#FBBF24'
                d='M44.7,-76.4C58.9,-69.2,71.8,-59.1,79.6,-46.3C87.4,-33.5,90.1,-18,87.9,-3.3C85.7,11.4,78.6,25.3,69.5,37.3C60.4,49.3,49.3,59.4,36.9,65.9C24.5,72.4,10.8,75.3,-2.3,79.2C-15.4,83.1,-27.8,88,-39.3,83.7C-50.8,79.4,-61.4,65.9,-70.3,51.8C-79.2,37.7,-86.4,23,-86.9,8.1C-87.4,-6.8,-81.2,-21.9,-72.1,-34.5C-63,-47.1,-51,-57.2,-38.3,-65.2C-25.6,-73.2,-12.3,-79.1,1.9,-82.4C16.1,-85.7,30.5,-73.6,44.7,-76.4Z'
                transform='translate(100 100)'
              />
            </svg>
          </div>
          <div className='relative z-10 container mx-auto'>
            <h2 className='mb-4 text-3xl font-bold text-gray-900'>
              Events specially curated for you!
            </h2>
            <p className='mb-6 text-gray-700'>
              Get event suggestions tailored to your interests! Don't let your
              favorite events slip away.
            </p>
            <button
              onClick={() => router.push('/login')}
              className='hover:bg-opacity-90 flex items-center rounded-md bg-[#1e1e2e] px-6 py-3 font-bold text-white transition-opacity'
            >
              Get Started <ArrowRight className='ml-2 h-5 w-5' />
            </button>
          </div>
        </section>

        {/* Trending Events */}
        <section>
          <h2 className='mb-6 text-2xl font-bold text-gray-900'>
            Trending Events around the World
          </h2>
          <div className='grid grid-cols-1 gap-6 md:grid-cols-3'>
            {trendingEvents.map((event) => (
              <EventCard key={event.id} event={event} />
            ))}
          </div>
          <div className='mt-8 text-center'>
            <Link
              href='/events'
              className='inline-block rounded-md border border-gray-300 px-8 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50'
            >
              See More
            </Link>
          </div>
        </section>

        {/* Subscription Banner */}
        <section className='rounded-xl bg-yellow-400 p-8 text-[#1e1e2e] md:p-12'>
          <div className='items-center justify-between md:flex'>
            <div className='mb-6 md:mb-0 md:w-1/2'>
              <h2 className='mb-2 text-2xl font-bold'>
                Subscribe to our Newsletter
              </h2>
              <p className='text-[#1e1e2e]/80'>
                Receive our weekly newsletter & updates with new events from
                your favorite organizers & venues.
              </p>
            </div>
            <div className='md:w-1/2 md:pl-8'>
              <div className='flex overflow-hidden rounded-md bg-white p-1'>
                <input
                  type='email'
                  placeholder='Enter your e-mail address'
                  className='flex-1 px-4 py-2 text-gray-700 focus:outline-none'
                />
                <button className='rounded-md bg-[#1e1e2e] px-6 py-2 font-medium text-white transition-colors hover:bg-gray-800'>
                  Subscribe
                </button>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
