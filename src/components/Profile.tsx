import React, { useState, useEffect } from 'react';
import { useStore } from './Store';
import { Camera } from 'lucide-react';

export const Profile: React.FC = () => {
  const { currentUser, updateProfile } = useStore();
  const [activeTab, setActiveTab] = useState<'info' | 'email' | 'password'>(
    'info'
  );
  const [isSaving, setIsSaving] = useState(false);

  // Form State
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    website: '',
    company: '',
    phone: '',
    address: '',
    city: '',
    country: '',
    pincode: '',
    avatar: '',
  });

  // Load user data
  useEffect(() => {
    if (currentUser) {
      setFormData({
        firstName:
          currentUser.firstName || currentUser.name.split(' ')[0] || '',
        lastName:
          currentUser.lastName ||
          currentUser.name.split(' ').slice(1).join(' ') ||
          '',
        website: currentUser.website || '',
        company: currentUser.company || '',
        phone: currentUser.phone || '',
        address: currentUser.address || '',
        city: currentUser.city || '',
        country: currentUser.country || '',
        pincode: currentUser.pincode || '',
        avatar: currentUser.avatar || '',
      });
    }
  }, [currentUser]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSave = async () => {
    if (!currentUser) return;
    setIsSaving(true);

    // Simulate API delay
    await new Promise((resolve) => setTimeout(resolve, 800));

    updateProfile(currentUser.id, {
      ...formData,
      name:
        `${formData.firstName} ${formData.lastName}`.trim() || currentUser.name,
    });

    setIsSaving(false);
    alert('Profile updated successfully!');
  };

  const renderSidebar = () => (
    <div className='w-full border-r border-gray-200 bg-gray-50/50 md:min-h-screen md:w-64'>
      <div className='p-6'>
        <h2 className='mb-6 text-xl font-bold text-gray-800'>
          Account Settings
        </h2>
        <nav className='space-y-1'>
          <button
            onClick={() => setActiveTab('info')}
            className={`w-full border-l-4 px-4 py-3 text-left text-sm font-medium transition-colors ${
              activeTab === 'info'
                ? 'border-[#1e1e2e] bg-white text-gray-900 shadow-sm'
                : 'border-transparent text-gray-500 hover:bg-gray-50 hover:text-gray-900'
            }`}
          >
            Account Info
          </button>
          <button
            onClick={() => setActiveTab('email')}
            className={`w-full border-l-4 px-4 py-3 text-left text-sm font-medium transition-colors ${
              activeTab === 'email'
                ? 'border-[#1e1e2e] bg-white text-gray-900 shadow-sm'
                : 'border-transparent text-gray-500 hover:bg-gray-50 hover:text-gray-900'
            }`}
          >
            Change Email
          </button>
          <button
            onClick={() => setActiveTab('password')}
            className={`w-full border-l-4 px-4 py-3 text-left text-sm font-medium transition-colors ${
              activeTab === 'password'
                ? 'border-[#1e1e2e] bg-white text-gray-900 shadow-sm'
                : 'border-transparent text-gray-500 hover:bg-gray-50 hover:text-gray-900'
            }`}
          >
            Password
          </button>
        </nav>
      </div>
    </div>
  );

  const renderAccountInfo = () => (
    <div className='animate-fade-in space-y-8'>
      <div>
        <h2 className='mb-8 border-b pb-4 text-2xl font-bold text-gray-900'>
          Account Information
        </h2>

        {/* Profile Photo */}
        <div className='mb-10'>
          <h3 className='mb-4 text-lg font-medium text-gray-900'>
            Profile Photo
          </h3>
          <div className='group relative inline-block'>
            <div className='h-32 w-32 overflow-hidden rounded-full border-4 border-gray-100 bg-gray-200 shadow-sm'>
              {formData.avatar ? (
                <img
                  src={formData.avatar}
                  alt='Profile'
                  className='h-full w-full object-cover'
                />
              ) : (
                <div className='flex h-full w-full items-center justify-center bg-gray-100 text-4xl font-bold text-gray-400'>
                  {formData.firstName?.[0]}
                </div>
              )}
            </div>
            <button className='absolute right-1 bottom-1 rounded-full border border-gray-200 bg-white p-2.5 text-gray-600 shadow-lg transition-all hover:scale-105 hover:text-[#1e1e2e]'>
              <Camera className='h-5 w-5' />
            </button>
          </div>
        </div>

        {/* Profile Information */}
        <div className='mb-12 space-y-6'>
          <h3 className='border-b pb-2 text-lg font-medium text-gray-900'>
            Profile Information
          </h3>

          <div className='max-w-3xl space-y-5'>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                First Name:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='firstName'
                  value={formData.firstName}
                  onChange={handleChange}
                  placeholder='Enter first name'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Last Name:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='lastName'
                  value={formData.lastName}
                  onChange={handleChange}
                  placeholder='Enter last name'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Website:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='website'
                  value={formData.website}
                  onChange={handleChange}
                  placeholder='Enter website'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Company:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='company'
                  value={formData.company}
                  onChange={handleChange}
                  placeholder='Enter company name'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
          </div>
        </div>

        {/* Contact Details */}
        <div className='space-y-6'>
          <div className='border-b pb-2'>
            <h3 className='text-lg font-medium text-gray-900'>
              Contact Details
            </h3>
            <p className='mt-1 text-sm text-gray-500'>
              These details are private and only used to contact you for
              ticketing or prizes.
            </p>
          </div>

          <div className='max-w-3xl space-y-5'>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Phone Number:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='phone'
                  value={formData.phone}
                  onChange={handleChange}
                  placeholder='Enter phone number'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Address:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='address'
                  value={formData.address}
                  onChange={handleChange}
                  placeholder='Enter address'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                City/Town:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='city'
                  value={formData.city}
                  onChange={handleChange}
                  placeholder='Enter city'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Country:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='country'
                  value={formData.country}
                  onChange={handleChange}
                  placeholder='Enter country'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
            <div className='grid grid-cols-1 items-center gap-4 md:grid-cols-12'>
              <label className='block text-sm font-medium text-gray-700 md:col-span-3'>
                Pincode:
              </label>
              <div className='md:col-span-9'>
                <input
                  type='text'
                  name='pincode'
                  value={formData.pincode}
                  onChange={handleChange}
                  placeholder='Enter pincode'
                  className='block w-full rounded-md border border-gray-300 px-4 py-2.5 shadow-sm focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
                />
              </div>
            </div>
          </div>
        </div>

        <div className='pt-8'>
          <button
            onClick={handleSave}
            disabled={isSaving}
            className='flex items-center rounded-lg bg-[#1e1e2e] px-8 py-3 font-medium text-white shadow-lg transition-colors hover:bg-[#2d2d44] disabled:opacity-70'
          >
            {isSaving ? (
              <>
                <span className='mr-2 h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent'></span>
                Saving...
              </>
            ) : (
              'Save My Profile'
            )}
          </button>
        </div>
      </div>
    </div>
  );

  const renderChangeEmail = () => (
    <div className='animate-fade-in max-w-2xl'>
      <h2 className='mb-6 border-b pb-4 text-2xl font-bold text-gray-900'>
        Change Email
      </h2>
      <div className='space-y-6'>
        <div className='space-y-2 rounded-lg border border-blue-100 bg-blue-50 p-4 text-blue-800'>
          <label className='block text-sm font-bold'>Current Email</label>
          <div className='text-lg'>{currentUser?.email}</div>
        </div>
        <div className='space-y-1'>
          <label className='block text-sm font-medium text-gray-700'>
            New Email
          </label>
          <input
            type='email'
            placeholder='Enter new email'
            className='block w-full rounded-md border border-gray-300 px-4 py-2.5 focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
          />
        </div>
        <div className='space-y-1'>
          <label className='block text-sm font-medium text-gray-700'>
            Confirm Email
          </label>
          <input
            type='email'
            placeholder='Enter again'
            className='block w-full rounded-md border border-gray-300 px-4 py-2.5 focus:border-[#1e1e2e] focus:ring-[#1e1e2e]'
          />
        </div>
        <div className='pt-4'>
          <button className='rounded-lg bg-[#1e1e2e] px-6 py-2.5 font-medium text-white shadow transition-colors hover:bg-[#2d2d44]'>
            Save New Email
          </button>
        </div>
      </div>
    </div>
  );

  const renderPassword = () => (
    <div className='animate-fade-in max-w-2xl'>
      <h2 className='mb-6 border-b pb-4 text-2xl font-bold text-gray-900'>
        Set Password
      </h2>
      <div className='space-y-6'>
        <div className='border-l-4 border-yellow-400 bg-yellow-50 p-4'>
          <div className='flex'>
            <div className='ml-3'>
              <p className='text-sm text-yellow-700'>
                A password has not been set for your account yet or you logged
                in via social media.
              </p>
            </div>
          </div>
        </div>
        <button className='rounded-lg bg-[#1e1e2e] px-6 py-2.5 font-medium text-white shadow transition-colors hover:bg-[#2d2d44]'>
          Set Password
        </button>
      </div>
    </div>
  );

  return (
    <div className='min-h-screen bg-white font-sans'>
      <div className='mx-auto flex min-h-screen max-w-7xl flex-col shadow-sm md:flex-row'>
        {/* Sidebar */}
        {renderSidebar()}

        {/* Main Content */}
        <div className='flex-1 bg-white p-6 md:p-12'>
          {activeTab === 'info' && renderAccountInfo()}
          {activeTab === 'email' && renderChangeEmail()}
          {activeTab === 'password' && renderPassword()}
        </div>
      </div>
    </div>
  );
};
