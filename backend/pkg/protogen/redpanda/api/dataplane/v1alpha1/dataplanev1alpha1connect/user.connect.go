// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: redpanda/api/dataplane/v1alpha1/user.proto

package dataplanev1alpha1connect

import (
	context "context"
	errors "errors"
	http "net/http"
	strings "strings"

	connect "connectrpc.com/connect"

	v1alpha1 "github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/dataplane/v1alpha1"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// UserServiceName is the fully-qualified name of the UserService service.
	UserServiceName = "redpanda.api.dataplane.v1alpha1.UserService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// UserServiceCreateUserProcedure is the fully-qualified name of the UserService's CreateUser RPC.
	UserServiceCreateUserProcedure = "/redpanda.api.dataplane.v1alpha1.UserService/CreateUser"
	// UserServiceUpdateUserProcedure is the fully-qualified name of the UserService's UpdateUser RPC.
	UserServiceUpdateUserProcedure = "/redpanda.api.dataplane.v1alpha1.UserService/UpdateUser"
	// UserServiceListUsersProcedure is the fully-qualified name of the UserService's ListUsers RPC.
	UserServiceListUsersProcedure = "/redpanda.api.dataplane.v1alpha1.UserService/ListUsers"
	// UserServiceDeleteUserProcedure is the fully-qualified name of the UserService's DeleteUser RPC.
	UserServiceDeleteUserProcedure = "/redpanda.api.dataplane.v1alpha1.UserService/DeleteUser"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	userServiceServiceDescriptor          = v1alpha1.File_redpanda_api_dataplane_v1alpha1_user_proto.Services().ByName("UserService")
	userServiceCreateUserMethodDescriptor = userServiceServiceDescriptor.Methods().ByName("CreateUser")
	userServiceUpdateUserMethodDescriptor = userServiceServiceDescriptor.Methods().ByName("UpdateUser")
	userServiceListUsersMethodDescriptor  = userServiceServiceDescriptor.Methods().ByName("ListUsers")
	userServiceDeleteUserMethodDescriptor = userServiceServiceDescriptor.Methods().ByName("DeleteUser")
)

// UserServiceClient is a client for the redpanda.api.dataplane.v1alpha1.UserService service.
type UserServiceClient interface {
	CreateUser(context.Context, *connect.Request[v1alpha1.CreateUserRequest]) (*connect.Response[v1alpha1.CreateUserResponse], error)
	UpdateUser(context.Context, *connect.Request[v1alpha1.UpdateUserRequest]) (*connect.Response[v1alpha1.UpdateUserResponse], error)
	ListUsers(context.Context, *connect.Request[v1alpha1.ListUsersRequest]) (*connect.Response[v1alpha1.ListUsersResponse], error)
	DeleteUser(context.Context, *connect.Request[v1alpha1.DeleteUserRequest]) (*connect.Response[v1alpha1.DeleteUserResponse], error)
}

// NewUserServiceClient constructs a client for the redpanda.api.dataplane.v1alpha1.UserService
// service. By default, it uses the Connect protocol with the binary Protobuf Codec, asks for
// gzipped responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply
// the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewUserServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) UserServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &userServiceClient{
		createUser: connect.NewClient[v1alpha1.CreateUserRequest, v1alpha1.CreateUserResponse](
			httpClient,
			baseURL+UserServiceCreateUserProcedure,
			connect.WithSchema(userServiceCreateUserMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updateUser: connect.NewClient[v1alpha1.UpdateUserRequest, v1alpha1.UpdateUserResponse](
			httpClient,
			baseURL+UserServiceUpdateUserProcedure,
			connect.WithSchema(userServiceUpdateUserMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listUsers: connect.NewClient[v1alpha1.ListUsersRequest, v1alpha1.ListUsersResponse](
			httpClient,
			baseURL+UserServiceListUsersProcedure,
			connect.WithSchema(userServiceListUsersMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deleteUser: connect.NewClient[v1alpha1.DeleteUserRequest, v1alpha1.DeleteUserResponse](
			httpClient,
			baseURL+UserServiceDeleteUserProcedure,
			connect.WithSchema(userServiceDeleteUserMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// userServiceClient implements UserServiceClient.
type userServiceClient struct {
	createUser *connect.Client[v1alpha1.CreateUserRequest, v1alpha1.CreateUserResponse]
	updateUser *connect.Client[v1alpha1.UpdateUserRequest, v1alpha1.UpdateUserResponse]
	listUsers  *connect.Client[v1alpha1.ListUsersRequest, v1alpha1.ListUsersResponse]
	deleteUser *connect.Client[v1alpha1.DeleteUserRequest, v1alpha1.DeleteUserResponse]
}

// CreateUser calls redpanda.api.dataplane.v1alpha1.UserService.CreateUser.
func (c *userServiceClient) CreateUser(ctx context.Context, req *connect.Request[v1alpha1.CreateUserRequest]) (*connect.Response[v1alpha1.CreateUserResponse], error) {
	return c.createUser.CallUnary(ctx, req)
}

// UpdateUser calls redpanda.api.dataplane.v1alpha1.UserService.UpdateUser.
func (c *userServiceClient) UpdateUser(ctx context.Context, req *connect.Request[v1alpha1.UpdateUserRequest]) (*connect.Response[v1alpha1.UpdateUserResponse], error) {
	return c.updateUser.CallUnary(ctx, req)
}

// ListUsers calls redpanda.api.dataplane.v1alpha1.UserService.ListUsers.
func (c *userServiceClient) ListUsers(ctx context.Context, req *connect.Request[v1alpha1.ListUsersRequest]) (*connect.Response[v1alpha1.ListUsersResponse], error) {
	return c.listUsers.CallUnary(ctx, req)
}

// DeleteUser calls redpanda.api.dataplane.v1alpha1.UserService.DeleteUser.
func (c *userServiceClient) DeleteUser(ctx context.Context, req *connect.Request[v1alpha1.DeleteUserRequest]) (*connect.Response[v1alpha1.DeleteUserResponse], error) {
	return c.deleteUser.CallUnary(ctx, req)
}

// UserServiceHandler is an implementation of the redpanda.api.dataplane.v1alpha1.UserService
// service.
type UserServiceHandler interface {
	CreateUser(context.Context, *connect.Request[v1alpha1.CreateUserRequest]) (*connect.Response[v1alpha1.CreateUserResponse], error)
	UpdateUser(context.Context, *connect.Request[v1alpha1.UpdateUserRequest]) (*connect.Response[v1alpha1.UpdateUserResponse], error)
	ListUsers(context.Context, *connect.Request[v1alpha1.ListUsersRequest]) (*connect.Response[v1alpha1.ListUsersResponse], error)
	DeleteUser(context.Context, *connect.Request[v1alpha1.DeleteUserRequest]) (*connect.Response[v1alpha1.DeleteUserResponse], error)
}

// NewUserServiceHandler builds an HTTP handler from the service implementation. It returns the path
// on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewUserServiceHandler(svc UserServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	userServiceCreateUserHandler := connect.NewUnaryHandler(
		UserServiceCreateUserProcedure,
		svc.CreateUser,
		connect.WithSchema(userServiceCreateUserMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	userServiceUpdateUserHandler := connect.NewUnaryHandler(
		UserServiceUpdateUserProcedure,
		svc.UpdateUser,
		connect.WithSchema(userServiceUpdateUserMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	userServiceListUsersHandler := connect.NewUnaryHandler(
		UserServiceListUsersProcedure,
		svc.ListUsers,
		connect.WithSchema(userServiceListUsersMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	userServiceDeleteUserHandler := connect.NewUnaryHandler(
		UserServiceDeleteUserProcedure,
		svc.DeleteUser,
		connect.WithSchema(userServiceDeleteUserMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/redpanda.api.dataplane.v1alpha1.UserService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case UserServiceCreateUserProcedure:
			userServiceCreateUserHandler.ServeHTTP(w, r)
		case UserServiceUpdateUserProcedure:
			userServiceUpdateUserHandler.ServeHTTP(w, r)
		case UserServiceListUsersProcedure:
			userServiceListUsersHandler.ServeHTTP(w, r)
		case UserServiceDeleteUserProcedure:
			userServiceDeleteUserHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedUserServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedUserServiceHandler struct{}

func (UnimplementedUserServiceHandler) CreateUser(context.Context, *connect.Request[v1alpha1.CreateUserRequest]) (*connect.Response[v1alpha1.CreateUserResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("redpanda.api.dataplane.v1alpha1.UserService.CreateUser is not implemented"))
}

func (UnimplementedUserServiceHandler) UpdateUser(context.Context, *connect.Request[v1alpha1.UpdateUserRequest]) (*connect.Response[v1alpha1.UpdateUserResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("redpanda.api.dataplane.v1alpha1.UserService.UpdateUser is not implemented"))
}

func (UnimplementedUserServiceHandler) ListUsers(context.Context, *connect.Request[v1alpha1.ListUsersRequest]) (*connect.Response[v1alpha1.ListUsersResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("redpanda.api.dataplane.v1alpha1.UserService.ListUsers is not implemented"))
}

func (UnimplementedUserServiceHandler) DeleteUser(context.Context, *connect.Request[v1alpha1.DeleteUserRequest]) (*connect.Response[v1alpha1.DeleteUserResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("redpanda.api.dataplane.v1alpha1.UserService.DeleteUser is not implemented"))
}
