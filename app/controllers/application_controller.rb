require "./config/environment"
require "./app/models/user"
class ApplicationController < Sinatra::Base

	configure do
		set :views, "app/views"
		enable :sessions
		set :session_secret, "password_security"
    end
    
    helpers do
		def logged_in?
			!!session[:user_id]
		end

		def current_user
			User.find(session[:user_id])
		end
	end

	get "/" do
		erb :index
	end

	get "/signup" do
		erb :signup
	end

	post "/signup" do
        # Creates a new user with params data from form.
        user = User.new(
            :username => params[:username],
            :password => params[:password]
        )
        # Due to has_secure_password, user cannot save without params[:password] input. If it's filled it can save and redirect to login, else it will direct user to failure.
        if user.save
            redirect '/login'
        else
            redirect '/failure'
        end
	end

	get "/login" do
		erb :login
	end

    post "/login" do
        # You've created a user during sign-up. But it doesn't mean you've logged in. Find the user with the same username. 
        user = User.find_by(:username => params[:username])
        # If user not equal to nil, therefore 'true'...
        # and user.authenticate => returns user
        # Log the user in by creating setting session[:user_id] = user.id
        #rediect to '/success'. Otherwise, redirect to '/failure'.
        if user && user.authenticate(params[:password])
            # This is creating the session of the spcific user.
            session[:user_id] = user.id
            redirect '/success'
        else
            redirect '/failure'
        end
	end

	get "/success" do
		if logged_in?
			erb :success
		else
			redirect "/login"
		end
	end

	get "/failure" do
		erb :failure
	end

	get "/logout" do
		session.clear
		redirect "/"
	end

	

end