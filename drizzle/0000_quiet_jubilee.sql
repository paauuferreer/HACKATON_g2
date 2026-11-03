CREATE TABLE `audit` (
	`id` text PRIMARY KEY NOT NULL,
	`actor` text NOT NULL,
	`event` text NOT NULL,
	`detail` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` text PRIMARY KEY NOT NULL,
	`source_key` text NOT NULL,
	`subject` text NOT NULL,
	`sender` text NOT NULL,
	`received_at` text NOT NULL,
	`body` text NOT NULL,
	`analysis` text NOT NULL,
	`status` text DEFAULT 'Pendiente' NOT NULL,
	`evidence_key` text NOT NULL,
	`evidence_hash` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `incidents_source_key_unique` ON `incidents` (`source_key`);--> statement-breakpoint
CREATE TABLE `operations` (
	`id` text PRIMARY KEY NOT NULL,
	`incident_id` text NOT NULL,
	`action` text NOT NULL,
	`type` text NOT NULL,
	`value` text NOT NULL,
	`actor` text NOT NULL,
	`reason` text NOT NULL,
	`state` text NOT NULL,
	`created_at` text NOT NULL,
	`response` text,
	`http_status` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `once_per_incident_target_action` ON `operations` (`incident_id`,`type`,`value`,`action`);--> statement-breakpoint
CREATE TABLE `target_locks` (
	`key` text PRIMARY KEY NOT NULL,
	`operation_id` text NOT NULL,
	`created_at` text NOT NULL
);
