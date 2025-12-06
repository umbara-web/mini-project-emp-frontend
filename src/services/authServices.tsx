import { User, UserRole, LoginResponse } from '../types/types';
import { generateReferralCode } from '../../lib/utils';

const USERS_KEY = 'booky_users';
const CURRENT_USER_KEY = 'booky_current_user';

// Mock database interactions
const getStoredUsers = (): User[] => {
  const users = localStorage.getItem(USERS_KEY);
  return users ? JSON.parse(users) : [];
};

const saveAllUsers = (users: User[]) => {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
};

const saveUser = (user: User & { password: string }) => {
  const users = getStoredUsers();
  users.push(user);
  saveAllUsers(users);
};

// Helper to calculate 3 months from now
const getThreeMonthsExpiry = () => {
  const date = new Date();
  date.setMonth(date.getMonth() + 3);
  return date.getTime();
};

export const authService = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 800));

    const users = getStoredUsers();
    // specific logic: simple password check (in real app, use bcrypt on backend)
    const user = users.find(
      (u: any) => u.email === email && u.password === password
    );

    if (!user) {
      throw new Error('Invalid email or password');
    }

    const { password: _, ...userWithoutPassword } = user as any;

    // Persist session (simplified)
    localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(userWithoutPassword));

    return {
      user: userWithoutPassword,
      token: 'mock-jwt-token-' + Date.now(),
    };
  },

  register: async (data: any): Promise<LoginResponse> => {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const users = getStoredUsers();

    if (users.find((u: any) => u.email === data.email)) {
      throw new Error('Email already exists');
    }

    // Referral Logic
    let hasCoupon = false;
    let couponExpiry = null;

    if (data.referralCodeInput) {
      // Find the Referrer
      const referrerIndex = users.findIndex(
        (u: User) => u.referralCode === data.referralCodeInput
      );

      if (referrerIndex !== -1) {
        // 1a. Referrer gets 10,000 points
        const referrer = users[referrerIndex];
        referrer.points = (referrer.points || 0) + 10000;

        // 1b. Points expire in 3 months
        // Note: In a real complex system, we might have a ledger of points with individual expiry.
        // For this spec, we update the expiry of the user's point balance.
        referrer.pointsExpiry = getThreeMonthsExpiry();

        users[referrerIndex] = referrer;
        saveAllUsers(users); // Save the updated referrer

        // 1a & 1c. New user gets Coupon valid for 3 months
        hasCoupon = true;
        couponExpiry = getThreeMonthsExpiry();
      } else {
        throw new Error('Invalid Referral Code');
      }
    }

    const newUser = {
      id: Date.now().toString(),
      name: data.name,
      email: data.email,
      phone: data.phone,
      role: data.role || UserRole.CUSTOMER,
      password: data.password, // In real backend, hash this!
      referralCode: generateReferralCode(),
      referredBy: data.referralCodeInput || null,
      createdAt: new Date().toISOString(),

      // Initial State
      profileImage: undefined,
      points: 0,
      pointsExpiry: null,
      hasCoupon: hasCoupon,
      couponExpiry: couponExpiry,
    };

    saveUser(newUser);

    // Do not remove password, as User type requires it
    localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(newUser));

    return {
      user: newUser,
      token: 'mock-jwt-token-' + Date.now(),
    };
  },

  updateProfile: async (
    userId: string,
    updates: Partial<User> & { password?: string; newPassword?: string }
  ): Promise<User> => {
    await new Promise((resolve) => setTimeout(resolve, 800));
    const users = getStoredUsers();
    const userIndex = users.findIndex((u: User) => u.id === userId);

    if (userIndex === -1) throw new Error('User not found');

    const currentUser = users[userIndex] as any;

    // Password Update Logic
    if (updates.newPassword) {
      // If changing password, verify old password (simplified)
      // In real app: bcrypt.compare(updates.password, user.passwordHash)
      if (currentUser.password !== updates.password) {
        throw new Error('Current password is incorrect');
      }
      currentUser.password = updates.newPassword;
    }

    // Update other fields
    const updatedUser = {
      ...currentUser,
      ...updates,
      password: currentUser.password, // ensure password persists (or is updated)
    };

    // Remove temporary password fields from the object stored in 'User' type part
    delete (updatedUser as any).newPassword;

    users[userIndex] = updatedUser;
    saveAllUsers(users);

    const { password: _, ...userWithoutSensitiveData } = updatedUser;

    // Update session if it's the current user
    const sessionUser = authService.getCurrentUser();
    if (sessionUser && sessionUser.id === userId) {
      localStorage.setItem(
        CURRENT_USER_KEY,
        JSON.stringify(userWithoutSensitiveData)
      );
    }

    return userWithoutSensitiveData;
  },

  logout: () => {
    localStorage.removeItem(CURRENT_USER_KEY);
  },

  getCurrentUser: (): User | null => {
    const user = localStorage.getItem(CURRENT_USER_KEY);
    return user ? JSON.parse(user) : null;
  },
};
