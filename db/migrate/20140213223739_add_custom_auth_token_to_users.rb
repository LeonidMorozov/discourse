class AddCustomAuthTokenToUsers < ActiveRecord::Migration
  def change
    add_column :users, :custom_auth_token, :string
    add_index :users, :custom_auth_token
  end
end
