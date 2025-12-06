'use client';

import React, { useState } from 'react';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useRouter } from 'next/navigation';
import { Input } from '../../components/ui/input';
import { authService } from '../../services/authServices';
import { Sparkles, Loader2 } from 'lucide-react';

const LoginSchema = Yup.object().shape({
  email: Yup.string()
    .email('Invalid email address')
    .required('Email is required'),
  password: Yup.string().required('Password is required'),
});

export default function LoginPage() {
  const router = useRouter();
  const [globalError, setGlobalError] = useState('');

  const formik = useFormik({
    initialValues: {
      email: '',
      password: '',
    },
    validationSchema: LoginSchema,
    onSubmit: async (values, { setSubmitting }) => {
      try {
        setGlobalError('');
        await authService.login(values.email, values.password);
        router.push('/home');
      } catch (error: any) {
        setGlobalError(error.message || 'Failed to login');
      } finally {
        setSubmitting(false);
      }
    },
  });

  return (
    <div className='px-4'>
      <div className='relative top-1/2 container mx-auto w-full max-w-[500px] translate-y-1/2 rounded-xl bg-white p-4 shadow-2xl md:p-6'>
        {/* Header */}
        <div className='mb-4 flex items-center justify-center gap-2'>
          <Sparkles className='h-6 w-6 text-blue-600' />
          <span className='text-xl font-bold text-gray-900'>Evently</span>
        </div>

        <h1 className='mb-2 text-2xl font-bold text-gray-900'>Login</h1>
        <p className='mb-8 text-sm text-gray-500'>
          Sign in to manage your library account.
        </p>

        {globalError && (
          <div className='mb-4 flex items-center gap-2 rounded-md border border-red-100 bg-red-50 p-3 text-sm text-red-600'>
            <div className='h-1.5 w-1.5 shrink-0 rounded-full bg-red-600' />
            {globalError}
          </div>
        )}

        <form onSubmit={formik.handleSubmit}>
          <Input
            label='Email'
            name='email'
            placeholder='johndoe@email.com'
            value={formik.values.email}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            error={formik.errors.email}
            touched={formik.touched.email}
            helperText='Enter your registered email address'
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
            helperText='Enter your secure password'
          />

          <button
            type='submit'
            disabled={formik.isSubmitting}
            className='mt-2 flex w-full items-center justify-center gap-2 rounded-full bg-blue-600 py-3 font-medium text-white shadow-lg transition-all duration-200 hover:-translate-y-0.5 hover:bg-blue-700 hover:shadow-xl'
          >
            {formik.isSubmitting && (
              <Loader2 className='h-4 w-4 animate-spin' />
            )}
            Login
          </button>

          <p className='mt-6 text-center text-sm text-gray-600'>
            Don't have an account?{' '}
            <span
              onClick={() => router.push('/register')}
              className='cursor-pointer font-medium text-blue-600 transition-colors hover:underline'
            >
              Register
            </span>
          </p>
        </form>
      </div>
    </div>
  );
}
