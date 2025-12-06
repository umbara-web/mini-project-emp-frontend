'use client';

import React, { useState } from 'react';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useRouter } from 'next/navigation';
import { Input } from '../../components/ui/input';
import { authService } from '../../services/authServices';
import { Sparkles, Loader2 } from 'lucide-react';
import { UserRole } from '../../types/types';

const RegisterSchema = Yup.object().shape({
  name: Yup.string().required('Name is required'),
  email: Yup.string()
    .email('Invalid email address')
    .required('Email is required'),
  phone: Yup.string()
    .matches(/^[0-9]+$/, 'Must be only digits')
    .min(10, 'Must be at least 10 digits')
    .required('Phone number is required'),
  password: Yup.string()
    .min(6, 'Password must be at least 6 characters')
    .required('Password is required'),
  confirmPassword: Yup.string()
    .oneOf([Yup.ref('password'), undefined], 'Passwords must match')
    .required('Confirm password is required'),
  role: Yup.mixed<UserRole>()
    .oneOf(Object.values(UserRole))
    .required('Role is required'),
  referralCodeInput: Yup.string().nullable(),
});

export default function RegisterPage() {
  const router = useRouter();
  const [globalError, setGlobalError] = useState('');

  const formik = useFormik({
    initialValues: {
      name: '',
      email: '',
      phone: '',
      password: '',
      confirmPassword: '',
      role: UserRole.CUSTOMER,
      referralCodeInput: '',
    },
    validationSchema: RegisterSchema,
    onSubmit: async (values, { setSubmitting }) => {
      try {
        setGlobalError('');
        await authService.register(values);
        router.push('/login');
      } catch (error: any) {
        setGlobalError(error.message || 'Failed to register');
      } finally {
        setSubmitting(false);
      }
    },
  });

  return (
    <div className='px-4'>
      <div className='animate-fade-in container mx-auto w-full max-w-[500px] rounded-xl bg-white p-4 shadow-2xl md:p-6'>
        {/* Header */}
        <div className='mb-4 flex items-center justify-center gap-2'>
          <Sparkles className='h-6 w-6 text-blue-600' />
          <span className='text-xl font-bold text-gray-900'>Evently</span>
        </div>

        <h1 className='mb-2 text-2xl font-bold text-gray-900'>Register</h1>
        <p className='mb-6 text-sm text-gray-500'>
          Create your account to start borrowing books or organizing events.
        </p>

        {globalError && (
          <div className='flex items-center gap-2 rounded-md border border-red-100 bg-red-50 text-sm text-red-600'>
            <div className='h-1.5 w-1.5 shrink-0 rounded-full bg-red-600' />
            {globalError}
          </div>
        )}

        <form onSubmit={formik.handleSubmit} className='space-y-0'>
          <Input
            label='Name'
            name='name'
            placeholder='John Doe'
            value={formik.values.name}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.name}
            touched={formik.touched.name}
            helperText='Enter your full legal name'
          />

          <Input
            label='Email'
            name='email'
            placeholder='johndoe@email.com'
            value={formik.values.email}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.email}
            touched={formik.touched.email}
            helperText="We'll use this for account verification"
          />

          <Input
            label='Nomor Handphone'
            name='phone'
            placeholder='081234567890'
            value={formik.values.phone}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.phone}
            touched={formik.touched.phone}
            helperText='Enter digits only, minimum 10 numbers'
          />

          {/* Role Selection */}
          <div className='mb-2'>
            <label className='mb-2 block text-sm font-semibold text-gray-900'>
              Select your Role
            </label>
            <div className='flex gap-4'>
              <label className='group flex w-full cursor-pointer items-center rounded-lg border p-3 transition-all hover:bg-gray-50 has-[:checked]:border-blue-500 has-[:checked]:bg-blue-50 has-[:checked]:ring-1 has-[:checked]:ring-blue-500'>
                <input
                  type='radio'
                  name='role'
                  value={UserRole.CUSTOMER}
                  checked={formik.values.role === UserRole.CUSTOMER}
                  onChange={formik.handleChange}
                  className='h-4 w-4 border-gray-300 text-blue-600 focus:ring-blue-500'
                />
                <span className='ml-2 text-sm text-gray-700 group-hover:text-gray-900'>
                  Customer
                </span>
              </label>
              <label className='group flex w-full cursor-pointer items-center rounded-lg border p-3 transition-all hover:bg-gray-50 has-[:checked]:border-blue-500 has-[:checked]:bg-blue-50 has-[:checked]:ring-1 has-[:checked]:ring-blue-500'>
                <input
                  type='radio'
                  name='role'
                  value={UserRole.ORGANIZER}
                  checked={formik.values.role === UserRole.ORGANIZER}
                  onChange={formik.handleChange}
                  className='h-4 w-4 border-gray-300 text-blue-600 focus:ring-blue-500'
                />
                <span className='ml-2 text-sm text-gray-700 group-hover:text-gray-900'>
                  Organizer
                </span>
              </label>
            </div>
          </div>

          <Input
            label='Referral Code (Optional)'
            name='referralCodeInput'
            placeholder='Enter code'
            value={formik.values.referralCodeInput}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.referralCodeInput}
            touched={formik.touched.referralCodeInput}
            helperText='Got a code from a friend? Enter it here'
          />

          <Input
            label='Password'
            name='password'
            type='password'
            placeholder='••••••••'
            value={formik.values.password}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.password}
            touched={formik.touched.password}
            helperText='Must be at least 6 characters long'
          />

          <Input
            label='Confirm Password'
            name='confirmPassword'
            type='password'
            placeholder='••••••••'
            value={formik.values.confirmPassword}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.confirmPassword}
            touched={formik.touched.confirmPassword}
            helperText='Re-enter your password to confirm'
          />

          <button
            type='submit'
            disabled={formik.isSubmitting}
            className='mt-2 flex w-full items-center justify-center gap-2 rounded-full bg-blue-600 py-3 font-medium text-white shadow-lg transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-700 hover:shadow-xl'
          >
            {formik.isSubmitting && (
              <Loader2 className='h-4 w-4 animate-spin' />
            )}
            Create Account
          </button>

          <p className='mt-6 text-center text-sm text-gray-600'>
            Already have an account?{' '}
            <span
              onClick={() => router.push('/login')}
              className='cursor-pointer font-medium text-blue-600 transition-colors hover:underline'
            >
              Log In
            </span>
          </p>
        </form>
      </div>
    </div>
  );
}
