import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import App from '../App';

describe('App', () => {
  it('renders login form by default', () => {
    render(<App />);
    expect(screen.getByText(/Login/i)).toBeInTheDocument();
  });

  it('shows dashboard nav button', () => {
    render(<App />);
    expect(screen.getByRole('button', { name: /dashboard/i })).toBeInTheDocument();
  });
});