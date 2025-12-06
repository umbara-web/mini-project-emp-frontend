import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useStore } from './Store';
import { EventCard } from '../components/EventCard';
import { EventCategory } from '../types/types';
import { Search, MapPin, SearchX } from 'lucide-react';
import useDebounce from '../hooks/useDebounce';

export const Events: React.FC = () => {
  const { events } = useStore();
  const [searchParams, setSearchParams] = useSearchParams();

  // Initialize state from URL params
  const initialSearch = searchParams.get('search') || '';
  const initialLocation = searchParams.get('location') || 'Mumbai';
  const initialDateFilter = searchParams.get('date');

  const [searchTerm, setSearchTerm] = useState(initialSearch);
  const [location, setLocation] = useState(initialLocation);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [priceType, setPriceType] = useState<'any' | 'free' | 'paid'>('any');

  // Date Filters State
  const [dateFilters, setDateFilters] = useState({
    today: initialDateFilter === 'today',
    tomorrow: initialDateFilter === 'tomorrow',
    thisWeek: initialDateFilter === 'week',
    thisWeekend: initialDateFilter === 'weekend',
  });

  const debouncedSearchTerm = useDebounce(searchTerm, 500);

  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      const term = debouncedSearchTerm.toLowerCase();
      const matchSearch =
        event.title.toLowerCase().includes(term) ||
        event.description.toLowerCase().includes(term);
      const matchCat =
        selectedCategories.length === 0 ||
        selectedCategories.includes(event.category);
      const matchPrice =
        priceType === 'any' ||
        (priceType === 'free' && event.price === 0) ||
        (priceType === 'paid' && event.price > 0);

      // Date Filtering Logic
      let matchDate = true;
      const hasDateFilters = Object.values(dateFilters).some(Boolean);

      if (hasDateFilters) {
        const eventDate = new Date(event.startDate);
        const now = new Date();

        // Normalize today start (00:00:00)
        const todayStart = new Date(
          now.getFullYear(),
          now.getMonth(),
          now.getDate()
        );

        // Today End (23:59:59)
        const todayEnd = new Date(todayStart);
        todayEnd.setDate(todayEnd.getDate() + 1);
        todayEnd.setMilliseconds(-1);

        // Tomorrow
        const tomorrowStart = new Date(todayStart);
        tomorrowStart.setDate(tomorrowStart.getDate() + 1);
        const tomorrowEnd = new Date(tomorrowStart);
        tomorrowEnd.setDate(tomorrowEnd.getDate() + 1);
        tomorrowEnd.setMilliseconds(-1);

        // This Week (Today until end of upcoming Sunday)
        const currentDay = now.getDay(); // 0 (Sun) to 6 (Sat)
        const daysUntilSunday = currentDay === 0 ? 0 : 7 - currentDay;
        const weekEnd = new Date(todayStart);
        weekEnd.setDate(weekEnd.getDate() + daysUntilSunday + 1);
        weekEnd.setMilliseconds(-1);

        // This Weekend (Saturday & Sunday)
        // If today is Sunday, weekend includes yesterday(Sat) and today(Sun).
        // If today is Mon-Sat, weekend is upcoming Sat & Sun.
        const daysUntilSaturday = (6 - currentDay + 7) % 7;
        const weekendStart = new Date(todayStart);
        // If today is Sunday (0), weekend started yesterday (-1)
        weekendStart.setDate(
          weekendStart.getDate() + (currentDay === 0 ? -1 : daysUntilSaturday)
        );
        const weekendEnd = new Date(weekendStart);
        weekendEnd.setDate(weekendEnd.getDate() + 2); // Sat + 2 days = Mon start
        weekendEnd.setMilliseconds(-1);

        const isToday = eventDate >= todayStart && eventDate <= todayEnd;
        const isTomorrow =
          eventDate >= tomorrowStart && eventDate <= tomorrowEnd;
        const isThisWeek = eventDate >= todayStart && eventDate <= weekEnd;
        const isThisWeekend =
          eventDate >= weekendStart && eventDate <= weekendEnd;

        matchDate =
          (dateFilters.today && isToday) ||
          (dateFilters.tomorrow && isTomorrow) ||
          (dateFilters.thisWeek && isThisWeek) ||
          (dateFilters.thisWeekend && isThisWeekend);
      }

      return (
        matchSearch && matchCat && matchPrice && matchDate && event.isPublished
      );
    });
  }, [events, debouncedSearchTerm, selectedCategories, priceType, dateFilters]);

  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const toggleDateFilter = (key: keyof typeof dateFilters) => {
    setDateFilters((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const clearFilters = () => {
    setSearchTerm('');
    setLocation('Mumbai');
    setSelectedCategories([]);
    setPriceType('any');
    setDateFilters({
      today: false,
      tomorrow: false,
      thisWeek: false,
      thisWeekend: false,
    });
    setSearchParams({});
  };

  // Sync URL with Search Term
  useEffect(() => {
    const params: any = {};
    if (debouncedSearchTerm) params.search = debouncedSearchTerm;
    if (location) params.location = location;
    // We don't sync complex date filters back to URL for simplicity in this MVP,
    // but we could if needed.
    setSearchParams(params);
  }, [debouncedSearchTerm, location, setSearchParams]);

  return (
    <div className='min-h-screen bg-gray-50'>
      {/* Header Search */}
      <div className='bg-[#1e1e2e] px-4 py-12'>
        <div className='mx-auto max-w-7xl text-center'>
          <h1 className='mb-6 text-3xl font-bold text-white'>
            Explore a world of events. Find what excites you!
          </h1>
          <div className='mx-auto flex max-w-4xl flex-col items-center rounded-lg bg-white p-1.5 md:flex-row'>
            <div className='mb-2 flex w-full flex-1 items-center px-4 md:mb-0'>
              <Search className='mr-2 h-5 w-5 text-gray-400' />
              <input
                type='text'
                placeholder='Search Events, Categories, Location,...'
                className='w-full py-3 text-gray-700 focus:outline-none'
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <div className='mx-2 hidden h-8 w-px bg-gray-200 md:block'></div>
            <div className='mb-2 flex w-full flex-none items-center px-4 md:mb-0 md:w-auto'>
              <MapPin className='mr-2 h-5 w-5 text-gray-400' />
              <select
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                className='cursor-pointer bg-transparent py-3 text-gray-700 focus:outline-none'
              >
                <option value='Mumbai'>Mumbai</option>
                <option value='Jakarta'>Jakarta</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <div className='mx-auto flex max-w-7xl flex-col gap-8 px-4 py-8 sm:px-6 md:flex-row lg:px-8'>
        {/* Sidebar Filters */}
        <div className='flex w-full space-y-8 md:w-64'>
          <div>
            <h3 className='mb-4 text-lg font-bold text-gray-900'>Filters</h3>

            <div className='mb-6'>
              <h4 className='mb-3 text-sm font-semibold text-gray-700'>
                Price
              </h4>
              <div className='space-y-2'>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    checked={priceType === 'free'}
                    onChange={() =>
                      setPriceType((prev) => (prev === 'free' ? 'any' : 'free'))
                    }
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                  />
                  <span className='text-sm text-gray-600'>Free</span>
                </label>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    checked={priceType === 'paid'}
                    onChange={() =>
                      setPriceType((prev) => (prev === 'paid' ? 'any' : 'paid'))
                    }
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                  />
                  <span className='text-sm text-gray-600'>Paid</span>
                </label>
              </div>
            </div>

            <div className='mb-6'>
              <h4 className='mb-3 text-sm font-semibold text-gray-700'>Date</h4>
              <div className='space-y-2 text-sm text-gray-600'>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                    checked={dateFilters.today}
                    onChange={() => toggleDateFilter('today')}
                  />
                  Today
                </label>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                    checked={dateFilters.tomorrow}
                    onChange={() => toggleDateFilter('tomorrow')}
                  />
                  Tomorrow
                </label>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                    checked={dateFilters.thisWeek}
                    onChange={() => toggleDateFilter('thisWeek')}
                  />
                  This Week
                </label>
                <label className='flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    className='text-primary-600 focus:ring-primary-500 mr-2 rounded'
                    checked={dateFilters.thisWeekend}
                    onChange={() => toggleDateFilter('thisWeekend')}
                  />
                  This Weekend
                </label>
              </div>
            </div>

            <div className='mb-6'>
              <h4 className='mb-3 text-sm font-semibold text-gray-700'>
                Category
              </h4>
              <div className='space-y-2 text-sm text-gray-600'>
                {Object.values(EventCategory).map((cat) => (
                  <label key={cat} className='flex cursor-pointer items-center'>
                    <input
                      type='checkbox'
                      checked={selectedCategories.includes(cat)}
                      onChange={() => toggleCategory(cat)}
                      className='text-primary-600 mr-2 rounded'
                    />
                    {cat}
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className='flex-1'>
          <div className='mb-6 flex items-center justify-between'>
            <p className='text-sm text-gray-500'>
              Showing {filteredEvents.length} Events
            </p>
            <div className='flex items-center'>
              <span className='mr-2 text-sm text-gray-500'>Sort by:</span>
              <div className='relative inline-block text-left'>
                <select className='focus:ring-primary-500 focus:border-primary-500 block w-full rounded-md border-gray-300 py-2 pr-8 pl-3 text-sm focus:outline-none'>
                  <option>Relevance</option>
                  <option>Date</option>
                  <option>Price: Low to High</option>
                </select>
              </div>
            </div>
          </div>

          {filteredEvents.length > 0 ? (
            <div className='grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3'>
              {filteredEvents.map((event) => (
                <EventCard key={event.id} event={event} />
              ))}
            </div>
          ) : (
            <div className='flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-300 bg-white py-16'>
              <div className='mb-4 rounded-full bg-gray-50 p-6'>
                <SearchX className='h-10 w-10 text-gray-400' />
              </div>
              <h3 className='mb-2 text-lg font-bold text-gray-900'>
                No events found
              </h3>
              <p className='mb-6 max-w-sm text-center text-gray-500'>
                We couldn't find any events matching your current filters. Try
                adjusting your search criteria.
              </p>
              <button
                onClick={clearFilters}
                className='rounded-lg bg-[#1e1e2e] px-6 py-2.5 font-medium text-white transition-colors hover:bg-[#2d2d44]'
              >
                Clear All Filters
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
