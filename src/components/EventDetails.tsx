'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useRouter } from 'next/navigation';
import { useStore } from './Store';
import { formatRupiah } from '../../lib/utils';
import {
  MapPin,
  Calendar,
  Clock,
  Share2,
  Star,
  Ticket,
  User,
  Gift,
  Coins,
  Check,
} from 'lucide-react';
import { Modal } from '../components/ui/modals';

export const EventDetails: React.FC = () => {
  const { id } = useParams();
  const router = useRouter();

  const {
    events,
    users,
    currentUser,
    createTransaction,
    toggleInterest,
    coupons,
    vouchers,
    reviews,
  } = useStore();

  const event = events.find((e) => e.id === id);
  const organizer = users.find((u) => u.id === event?.organizerId);
  const relatedEvents = events
    .filter((e) => e.category === event?.category && e.id !== event?.id)
    .slice(0, 3);
  const eventReviews = reviews.filter((r) => r.eventId === event?.id);

  const [ticketQty, setTicketQty] = useState(1);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  // Transaction State
  const [usePoints, setUsePoints] = useState(false);
  const [promoCode, setPromoCode] = useState('');
  const [appliedPromo, setAppliedPromo] = useState<{
    type: 'coupon' | 'voucher';
    id: string;
    amount: number;
  } | null>(null);
  const [promoError, setPromoError] = useState('');

  if (!event) return <div className='py-20 text-center'>Event not found</div>;

  const isInterested = currentUser?.interestedEventIds?.includes(event.id);

  // Calculate Totals
  const basePrice = event.price * ticketQty;
  let discount = 0;

  // 1. Apply Promo (Voucher/Coupon)
  if (appliedPromo) {
    discount += appliedPromo.amount;
  }

  // 2. Apply Points (Max logic handled here visually, simpler logic in store)
  let pointsDiscount = 0;
  if (usePoints && currentUser) {
    // Max points we can use is the remaining price
    const remainingPrice = Math.max(0, basePrice - discount);
    pointsDiscount = Math.min(currentUser.points, remainingPrice);
  }

  const finalPrice = Math.max(0, basePrice - discount - pointsDiscount);

  const handleApplyPromo = () => {
    setPromoError('');
    setAppliedPromo(null);
    if (!promoCode) return;

    // Check Event Vouchers
    const voucher = vouchers.find(
      (v) => v.code === promoCode && v.eventId === event.id
    );
    if (voucher) {
      const disc = basePrice * (voucher.discountPercentage / 100);
      setAppliedPromo({ type: 'voucher', id: voucher.id, amount: disc });
      return;
    }

    // Check Global Coupons (User specific)
    const coupon = coupons.find(
      (c) => c.code === promoCode && c.userId === currentUser?.id && !c.isUsed
    );
    if (coupon) {
      setAppliedPromo({
        type: 'coupon',
        id: coupon.id,
        amount: coupon.discountAmount,
      });
      return;
    }

    setPromoError('Invalid or expired code.');
  };

  const handleBuy = async () => {
    if (!currentUser) {
      router.push('/login');
      return;
    }
    setIsProcessing(true);
    try {
      const couponId =
        appliedPromo?.type === 'coupon' ? appliedPromo.id : undefined;
      const voucherId =
        appliedPromo?.type === 'voucher' ? appliedPromo.id : undefined;
      const pointsToUse = usePoints ? pointsDiscount : 0;

      const success = await createTransaction(
        event.id,
        ticketQty,
        pointsToUse,
        couponId,
        voucherId
      );
      if (success) {
        setIsConfirmOpen(false);
        router.push('/my-tickets');
      } else {
        alert('Transaction failed. Seats might be full.');
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const handleInterestClick = () => {
    if (currentUser) toggleInterest(event.id);
    else alert('Please log in.');
  };

  const formatDateToICS = (date: Date) =>
    date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

  const handleAddToCalendar = () => {
    const icsContent = `BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nSUMMARY:${event.title}\nDTSTART:${formatDateToICS(new Date(event.startDate))}\nDTEND:${formatDateToICS(new Date(event.endDate))}\nLOCATION:${event.location}\nEND:VEVENT\nEND:VCALENDAR`;
    const blob = new Blob([icsContent], { type: 'text/calendar' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'event.ics';
    link.click();
  };

  const dateStr = new Date(event.startDate).toLocaleDateString('en-GB', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });

  return (
    <div className='min-h-screen bg-white pb-12'>
      <div className='mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8'>
        <button
          onClick={() => router.back()}
          className='mb-6 flex items-center text-gray-500 hover:text-gray-900'
        >
          ← Back
        </button>

        {/* Banner & Header (Similar to previous) */}
        <div className='relative mb-8 h-[350px] w-full overflow-hidden rounded-2xl bg-gray-100 shadow-lg'>
          <img
            src={event.image}
            alt={event.title}
            className='h-full w-full object-cover'
          />
          <div className='absolute right-4 bottom-4 rounded-lg bg-white/90 px-4 py-2 text-sm font-bold shadow-sm backdrop-blur-md'>
            {event.category}
          </div>
        </div>

        <div className='mb-8 flex items-start justify-between'>
          <h1 className='max-w-3xl text-3xl font-bold text-gray-900'>
            {event.title}
          </h1>
          <div className='flex space-x-3'>
            <button
              onClick={handleInterestClick}
              className={`rounded-full border p-2 ${isInterested ? 'border-yellow-400 bg-yellow-50 text-yellow-500' : 'border-gray-300'}`}
            >
              <Star
                className={`h-6 w-6 ${isInterested ? 'fill-current' : ''}`}
              />
            </button>
            <button className='rounded-full border border-gray-300 p-2'>
              <Share2 className='h-6 w-6 text-gray-600' />
            </button>
          </div>
        </div>

        <div className='grid grid-cols-1 gap-12 lg:grid-cols-3'>
          <div className='space-y-10 lg:col-span-2'>
            <section className='space-y-3'>
              <div className='flex items-center text-gray-700'>
                <Calendar className='mr-3 h-5 w-5 text-[#1e1e2e]' />
                <span>{dateStr}</span>
              </div>
              <div className='flex items-center text-gray-700'>
                <MapPin className='mr-3 h-5 w-5 text-[#1e1e2e]' />
                <span>{event.location}</span>
              </div>
              <button
                onClick={handleAddToCalendar}
                className='text-primary-600 ml-8 text-sm font-medium'
              >
                + Add to Calendar
              </button>
            </section>

            {/* Organizer Section */}
            <section className='flex items-center rounded-xl border border-gray-100 bg-gray-50 p-6'>
              <div className='mr-4 h-14 w-14 overflow-hidden rounded-full bg-gray-200'>
                <img
                  src={
                    organizer?.avatar ||
                    `https://ui-avatars.com/api/?name=${organizer?.name}`
                  }
                  alt=''
                  className='h-full w-full object-cover'
                />
              </div>
              <div>
                <h4 className='font-bold text-gray-900'>{organizer?.name}</h4>
                <p className='text-xs text-gray-500'>Organizer</p>
              </div>
            </section>

            <section>
              <h3 className='mb-4 text-xl font-bold text-gray-900'>About</h3>
              <p className='leading-relaxed text-gray-600'>
                {event.description}
              </p>
            </section>

            {/* Reviews Section */}
            <section>
              <h3 className='mb-4 text-xl font-bold text-gray-900'>
                Reviews ({eventReviews.length})
              </h3>
              {eventReviews.length > 0 ? (
                <div className='space-y-4'>
                  {eventReviews.map((r) => (
                    <div key={r.id} className='border-b pb-4'>
                      <div className='mb-1 flex items-center'>
                        {[...Array(5)].map((_, i) => (
                          <Star
                            key={i}
                            className={`h-4 w-4 ${i < r.rating ? 'fill-current text-yellow-400' : 'text-gray-300'}`}
                          />
                        ))}
                      </div>
                      <p className='text-sm text-gray-600'>"{r.comment}"</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className='text-gray-500 italic'>No reviews yet.</p>
              )}
            </section>
          </div>

          <div className='lg:col-span-1'>
            <div className='sticky top-24 rounded-xl border border-gray-100 bg-white p-6 shadow-xl'>
              <button
                onClick={() => setIsConfirmOpen(true)}
                className='w-full rounded-lg bg-[#facc15] py-4 text-lg font-bold text-[#1e1e2e] shadow-md hover:bg-yellow-400'
              >
                <Ticket className='mr-2 inline h-5 w-5' /> Buy Tickets
              </button>
              <div className='mt-4 rounded-lg bg-gray-50 p-4'>
                <p className='font-bold text-gray-900'>
                  {event.price === 0 ? 'Free' : formatRupiah(event.price)}
                </p>
                <p className='text-xs text-green-600'>
                  {event.seatsAvailable} seats left
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Purchase Modal with Points & Coupons */}
        <Modal
          isOpen={isConfirmOpen}
          onClose={() => setIsConfirmOpen(false)}
          title='Checkout'
        >
          <div className='space-y-6'>
            <div className='flex items-center justify-between border-b border-gray-100 py-2'>
              <span className='font-medium text-gray-700'>Quantity</span>
              <div className='flex items-center space-x-4'>
                <button
                  onClick={() => setTicketQty(Math.max(1, ticketQty - 1))}
                  className='h-8 w-8 rounded bg-gray-200'
                >
                  -
                </button>
                <span className='font-bold'>{ticketQty}</span>
                <button
                  onClick={() => setTicketQty(Math.min(5, ticketQty + 1))}
                  className='h-8 w-8 rounded bg-gray-200'
                >
                  +
                </button>
              </div>
            </div>

            {/* 1. Points Section */}
            {currentUser && currentUser.points > 0 && (
              <div className='flex items-center justify-between rounded-lg bg-blue-50 p-4'>
                <div className='flex items-center'>
                  <Coins className='mr-2 h-5 w-5 text-blue-600' />
                  <div>
                    <p className='text-sm font-bold text-blue-800'>
                      Use Points
                    </p>
                    <p className='text-xs text-blue-600'>
                      Balance: {currentUser.points}
                    </p>
                  </div>
                </div>
                <label className='relative inline-flex cursor-pointer items-center'>
                  <input
                    type='checkbox'
                    className='peer sr-only'
                    checked={usePoints}
                    onChange={(e) => setUsePoints(e.target.checked)}
                  />
                  <div className="peer h-6 w-11 rounded-full bg-gray-200 peer-checked:bg-blue-600 peer-focus:outline-none after:absolute after:top-[2px] after:left-[2px] after:h-5 after:w-5 after:rounded-full after:border after:border-gray-300 after:bg-white after:transition-all after:content-[''] peer-checked:after:translate-x-full peer-checked:after:border-white"></div>
                </label>
              </div>
            )}

            {/* 2. Promo Code Section */}
            <div>
              <label className='mb-1 block text-sm font-medium text-gray-700'>
                Promo Code
              </label>
              <div className='flex'>
                <input
                  type='text'
                  className='flex-1 rounded-l-md border border-gray-300 px-3 py-2 text-sm uppercase'
                  placeholder='VOUCHER123'
                  value={promoCode}
                  onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
                />
                <button
                  onClick={handleApplyPromo}
                  className='rounded-r-md bg-gray-800 px-4 text-sm text-white hover:bg-gray-700'
                >
                  Apply
                </button>
              </div>
              {promoError && (
                <p className='mt-1 text-xs text-red-500'>{promoError}</p>
              )}
              {appliedPromo && (
                <p className='mt-1 flex items-center text-xs text-green-600'>
                  <Check className='mr-1 h-3 w-3' /> Applied: -
                  {formatRupiah(appliedPromo.amount)}
                </p>
              )}
            </div>

            {/* Summary */}
            <div className='space-y-2 border-t pt-4 text-sm'>
              <div className='flex justify-between text-gray-500'>
                <span>Subtotal</span>
                <span>{formatRupiah(basePrice)}</span>
              </div>
              {discount > 0 && (
                <div className='flex justify-between text-green-600'>
                  <span>Discount</span>
                  <span>-{formatRupiah(discount)}</span>
                </div>
              )}
              {usePoints && pointsDiscount > 0 && (
                <div className='flex justify-between text-blue-600'>
                  <span>Points Used</span>
                  <span>-{formatRupiah(pointsDiscount)}</span>
                </div>
              )}
              <div className='mt-2 flex justify-between border-t pt-2 text-lg font-bold text-gray-900'>
                <span>Total</span>
                <span>{formatRupiah(finalPrice)}</span>
              </div>
            </div>

            <button
              onClick={handleBuy}
              disabled={isProcessing}
              className='w-full rounded-lg bg-[#1e1e2e] py-3.5 font-bold text-white hover:bg-[#2d2d44] disabled:opacity-70'
            >
              {isProcessing ? 'Processing...' : 'Pay & Confirm'}
            </button>
          </div>
        </Modal>
      </div>
    </div>
  );
};
