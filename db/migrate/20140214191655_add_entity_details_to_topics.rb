class AddEntityDetailsToTopics < ActiveRecord::Migration
  def change
	  add_column :topics, :entity_type, :string
	  add_column :topics, :entity_id, :integer
	  add_index :topics, [:entity_type, :entity_id]
  end
end
