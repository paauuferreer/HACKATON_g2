ALTER TABLE `incidents` ADD `duplicate_of` text;--> statement-breakpoint
ALTER TABLE `incidents` ADD `group_key` text;--> statement-breakpoint
ALTER TABLE `incidents` ADD `revision` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `incidents` ADD `updated_at` text;