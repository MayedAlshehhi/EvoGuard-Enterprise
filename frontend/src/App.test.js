import { render, screen } from "@testing-library/react";
import App from "./App";

jest.mock("leaflet", () => ({
  Icon: function Icon(options) {
    this.options = options;
  },
}));

jest.mock("react-leaflet", () => ({
  MapContainer: ({ children }) => <div data-testid="threat-map">{children}</div>,
  TileLayer: () => null,
  Marker: ({ children }) => <div>{children}</div>,
  Popup: ({ children }) => <div>{children}</div>,
  Polyline: () => null,
  CircleMarker: ({ children }) => <div>{children}</div>,
}));

beforeEach(() => {
  window.localStorage.clear();
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ authenticated: false }),
    })
  );
});

afterEach(() => {
  jest.restoreAllMocks();
});

test("renders EvoGuard login screen for signed-out users", async () => {
  render(<App />);

  expect(screen.getByRole("heading", { name: /evoguard/i })).toBeInTheDocument();
  expect(await screen.findByPlaceholderText(/username/i)).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /login/i })).toBeInTheDocument();
});
