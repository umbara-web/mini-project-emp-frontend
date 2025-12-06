import React, { useState } from 'react';
import { Eye, EyeOff, AlertCircle, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
  touched?: boolean;
  helperText?: string;
}

export const Input: React.FC<InputProps> = ({
  label,
  error,
  touched,
  helperText,
  className,
  type = 'text',
  onFocus,
  onBlur,
  ...props
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [isFocused, setIsFocused] = useState(false);

  const isPassword = type === 'password';
  const hasError = touched && error;
  // Show helper text when focused, unless there is an error to show
  const showHelper = isFocused && !hasError && helperText;

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    setIsFocused(true);
    if (onFocus) onFocus(e);
  };

  const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    setIsFocused(false);
    if (onBlur) onBlur(e);
  };

  return (
    <div className='group mb-4 w-full'>
      <label
        className={cn(
          'mb-1.5 block text-sm font-semibold transition-colors duration-200',
          hasError
            ? 'text-red-600'
            : isFocused
              ? 'text-blue-600'
              : 'text-gray-900'
        )}
      >
        {label}
      </label>
      <div className='relative'>
        <input
          type={isPassword ? (showPassword ? 'text' : 'password') : type}
          onFocus={handleFocus}
          onBlur={handleBlur}
          className={cn(
            'w-full rounded-lg border bg-white px-4 py-3 text-gray-900 transition-all duration-200 outline-none',
            hasError
              ? 'border-red-500 focus:ring-4 focus:ring-red-100'
              : 'border-gray-200 focus:border-blue-500 focus:ring-4 focus:ring-blue-50',
            className
          )}
          {...props}
        />
        {isPassword && (
          <button
            type='button'
            onClick={togglePasswordVisibility}
            className='absolute top-1/2 right-3 -translate-y-1/2 text-gray-400 transition-colors hover:text-gray-600 focus:outline-none'
          >
            {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
          </button>
        )}
      </div>

      {/* Feedback Message Area */}
      <div className='mt-1.5 min-h-[20px] overflow-hidden'>
        {hasError && (
          <p className='animate-slide-in flex items-center gap-1.5 text-xs font-medium text-red-500'>
            <AlertCircle size={12} className='shrink-0' />
            {error}
          </p>
        )}
        {showHelper && (
          <p className='animate-slide-in flex items-center gap-1.5 text-xs font-medium text-blue-600'>
            <Info size={12} className='shrink-0' />
            {helperText}
          </p>
        )}
      </div>
    </div>
  );
};
