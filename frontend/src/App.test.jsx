import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import '@testing-library/jest-dom'
import App from './App'

describe('App', () => {
  it('renders without crashing', () => {
    const { getByText } = render(<App />)
    expect(getByText(/Login/i)).toBeTruthy()
  })
})
