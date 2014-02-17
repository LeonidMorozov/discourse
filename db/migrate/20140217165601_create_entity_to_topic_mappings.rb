class CreateEntityToTopicMappings < ActiveRecord::Migration
  def change
    create_table :entity_to_topic_mappings do |t|
      t.string :entity_type
      t.integer :entity_id
      t.integer :topic_id

      t.timestamps
    end
    add_index :entity_to_topic_mappings, [:entity_type, :entity_id]
    add_index :entity_to_topic_mappings, :topic_id
  end
end
