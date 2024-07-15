const std = @import("std");
const cedar = @import("cedar");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var policySet = try cedar.parse(
        allocator,
        // 👇 the policy template defines the rules for who can do what and when
        \\permit (
        \\    principal == PhotoApp::User::"alice",
        \\    action == PhotoApp::Action::"viewPhoto",
        \\    resource == PhotoApp::Photo::"vacationPhoto.jpg"
        \\);
        \\
        \\permit (
        \\    principal == PhotoApp::User::"stacey",
        \\    action == PhotoApp::Action::"viewPhoto",
        \\    resource
        \\)
        \\when { resource in PhotoApp::Account::"stacey" };
        ,
    );
    defer policySet.deinit();

    // 👇 an Authorizer computes an answer the question "can this y do y with z?"
    const result = cedar.Authorizer.init().isAuthorized(.{
        // 👇 the principal is the actor in question
        .principal = cedar.EntityUID.init("PhotoApp::User", "alice"),
        // 👇 the action is what the principal is requesting to do
        .action = cedar.EntityUID.init("PhotoApp::Action", "viewPhoto"),
        // 👇 the resource is what the action applies to
        .resource = cedar.EntityUID.init("PhotoApp::Photo", "vacationPhoto.jpg"),
    }, policySet, .{});

    // 👇 do something with the authorization decision. the default is deny unless permitted
    switch (result.decision) {
        .allow => std.debug.print("yes alice can view vacationPhoto.jpg", .{}),
        .deny => std.debug.print("no alice can't view vacationPhoto.jpg", .{}),
    }
}
