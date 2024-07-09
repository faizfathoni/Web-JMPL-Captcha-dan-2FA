<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Providers\RouteServiceProvider;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login()
    {
        $showCaptcha = session()->get('login_attempts', 0) >= 3;
        return view('auth.login', compact('showCaptcha'));
    }

    public function loginPost(Request $request)
    {
        $loginAttempts = session()->get('login_attempts', 0);
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];

        if ($loginAttempts >= 3) {
            $rules['g-recaptcha-response'] = 'required|captcha';
        }

        // Validate form data including captcha
        $credentials = $request->validate($rules);

        $remember = $request->has('rememberMe');

        // If captcha is valid, attempt to authenticate the user
        if (Auth::attempt($request->only('email', 'password'), $remember)) {
            // Check if user has two-factor authentication enabled
            if (Auth::user()->two_factor_secret) {
                // Redirect user to two-factor challenge view
                return view('auth.two-factor-challenge');
            }

            // If not, clear login attempts and proceed to intended route
            $request->session()->forget('login_attempts');
            return redirect()->intended(RouteServiceProvider::HOME);
        }

        // If authentication fails, increment login attempts and redirect back with error message
        session()->put('login_attempts', $loginAttempts + 1);
        return back()->withErrors(['email' => "Your email or password doesn't match."]);
    }

    public function register()
    {
        return view('auth.register');
    }

    public function registerPost(Request $request)
    {
        Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|unique:users',
            'password' => 'required',
            ])->validate();

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return redirect(RouteServiceProvider::HOME);
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect()->route('login');
    }
}
