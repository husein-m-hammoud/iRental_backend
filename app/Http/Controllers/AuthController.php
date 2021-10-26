<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

  /**
   *
   */
  public function __construct() {

    $this->middleware('auth:api', ['except' => ['login', 'register']]);
  }

  /**
   *
   */
  public function login(Request $request) {

    ## Field Validation
    $validator = Validator::make($request->all(), [
      'email' => 'required|email',
      'password' => 'required|string|min:6'
    ]);

    ## Failed Validation
    if ($validator->fails()) {

      ## return Bad Request
      return response()->json($validator->errors(), 400);

    }

    ## One day token validity
    $token_validity = 24 * 60;

    $this->guard()->factory()->setTTL($token_validity);

    ## Wrong Email or Password
    if (!$token = $this->guard()->attempt($validator->validated())) {

      ## return Unauthorized
      return response()->json(['error' => 'unauthorized'], 401);

    }

    ## Successful Login
    return $this->respondWithToken($token);
  }

  /**
   *
   */
  public function register(Request $request) {

    ## Field Validation
    $validator = Validator::make($request->all(), [
      'name' => 'required|string|between:2,100',
      'email' => 'required|email|unique:users',
      'password' => 'required|confirmed|min:6'
    ]);

    ## Failed Validation
    if ($validator->fails()) {

      ## return Unprocessable Entity
      return response()->json($validator->errors(), 422);

    }

    ## Bcrypt Password
    $user = User::create(array_merge(
      $validator->validated(),
      ['password', bcrypt($request->password)]
    ));

    ## Successful User Creation
    return response()->json(['message' => 'User created successfully', 'user' => $user]);

  }

  /**
   *
   */
  public function logout() {

    $this->guard()->logout();

    ## Successful logout
    return response()->json(['message' => 'User logged out successfully']);

  }

  /**
   *
   */
  public function profile() {

    return response()->json($this->guard()->user());
  }

  /**
   *
   */
  public function refresh() {

    return $this->respondWithToken($this->guard()->refresh());
  }

  /**
   *
   */
  protected function respondWithToken($token) {

    return response()->json([
      'token' => $token,
      'token_type' => 'bearer',
      'token_validity' => $this->guard()->factory()->getTTL() * 60
    ]);
  }

  /**
   *
   */
  protected function guard() {

    return Auth::guard();
  }
}