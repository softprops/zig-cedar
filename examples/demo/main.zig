const std = @import("std");
const cedar = @import("cedar");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var policySet = try cedar.parse(
        allocator,
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

    for (policySet.policies) |p| {
        std.debug.print("parsed policy {s}\n", .{p});
    }

    var authorizer = cedar.Authorizer.init();
    const result = authorizer.isAuthorized(.{
        .principal = cedar.EntityUID.init("PhotoApp::User", "alice"),
        .action = cedar.EntityUID.init("PhotoApp::Action", "viewPhoto"),
        .resource = cedar.EntityUID.init("PhotoApp::Photo", "vacationPhoto.jpg"),
        .context = .{},
    }, policySet, .{});

    std.debug.print("authorization result {any}\n", .{result});
}
