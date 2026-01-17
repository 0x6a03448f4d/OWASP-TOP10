# API03: Broken Object Property Level Authorization - Prevention

## Table of Contents
- [Core Prevention Principles](#core-prevention-principles)
- [Data Transfer Objects (DTOs)](#data-transfer-objects-dtos)
- [Preventing Excessive Data Exposure](#preventing-excessive-data-exposure)
- [Preventing Mass Assignment](#preventing-mass-assignment)
- [Framework-Specific Implementations](#framework-specific-implementations)
- [Testing and Validation](#testing-and-validation)
- [Security Checklist](#security-checklist)

## Core Prevention Principles

### The Golden Rules

1. **Never serialize database models directly** - Always use DTOs/serializers
2. **Use allowlists, not denylists** - Explicitly define allowed fields
3. **Separate read and write schemas** - Different fields for input vs output
4. **Implement role-based field filtering** - Admins see more than users
5. **Validate and sanitize all input** - Never trust client-provided data
6. **Use read-only fields** - Mark fields that should never be modified
7. **Test with multiple user roles** - Verify field access per role

### Defense in Depth

```
Layer 1: DTOs/Serializers       ← Define allowed fields
Layer 2: Schema Validation      ← Validate field types and values
Layer 3: Authorization Checks   ← Verify user can access field
Layer 4: Auditing               ← Log sensitive field access
Layer 5: Monitoring             ← Detect anomalous patterns
```

## Data Transfer Objects (DTOs)

### What Are DTOs?

Data Transfer Objects are dedicated classes that define exactly which fields are exposed or accepted by an API endpoint. They act as a contract between your API and clients.

### Benefits of DTOs

- ✅ **Security**: Control exactly what fields are exposed/accepted
- ✅ **Versioning**: Different DTOs for API v1, v2, etc.
- ✅ **Documentation**: Clear API contracts
- ✅ **Validation**: Type safety and business rules
- ✅ **Decoupling**: API independent from database schema

### DTO Architecture Pattern

```python
# Database Model (Internal - Never expose directly)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password_hash = db.Column(db.String(255))
    api_key = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    salary = db.Column(db.Integer)
    ssn = db.Column(db.String(11))
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)

# Output DTO (What API returns)
class UserPublicDTO:
    id: int
    username: str
    email: str
    created_at: datetime
    # password_hash: NOT included
    # api_key: NOT included
    # is_admin: NOT included
    # salary: NOT included
    # ssn: NOT included

# Input DTO (What API accepts for updates)
class UserUpdateDTO:
    username: str
    email: str
    # is_admin: NOT allowed
    # salary: NOT allowed
    # created_at: NOT allowed (read-only)

# Admin Output DTO (What admins see)
class UserAdminDTO:
    id: int
    username: str
    email: str
    is_admin: bool
    created_at: datetime
    updated_at: datetime
    last_login_ip: str
    # password_hash: STILL not included
    # api_key: STILL not included
    # ssn: STILL not included (separate endpoint)
```

## Preventing Excessive Data Exposure

### Strategy 1: Use Explicit Serializers (Marshmallow)

```python
from marshmallow import Schema, fields

# ❌ VULNERABLE: Automatic serialization
class VulnerableUserSchema(Schema):
    class Meta:
        model = User  # Serializes ALL fields from model
        fields = "__all__"  # Exposes everything!

# ✅ SECURE: Explicit field definition
class UserPublicSchema(Schema):
    """Public user profile - safe for any authenticated user"""
    id = fields.Int(dump_only=True)
    username = fields.Str()
    email = fields.Email()
    created_at = fields.DateTime(dump_only=True)
    # No password_hash, api_key, is_admin, salary, ssn

class UserPrivateSchema(UserPublicSchema):
    """User's own profile - includes private info"""
    phone = fields.Str()
    address = fields.Str()
    # Still no password_hash, api_key, is_admin, salary

class UserAdminSchema(UserPrivateSchema):
    """Admin view - includes admin-only fields"""
    is_admin = fields.Bool()
    last_login_ip = fields.Str()
    failed_login_attempts = fields.Int()
    # Still no password_hash (never expose)

# Usage in endpoint
@app.route('/api/users/<int:user_id>')
@require_auth
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Choose schema based on relationship and role
    if current_user.is_admin:
        schema = UserAdminSchema()
    elif current_user.id == user_id:
        schema = UserPrivateSchema()
    else:
        schema = UserPublicSchema()
    
    return jsonify(schema.dump(user))
```

### Strategy 2: Use Pydantic Models (FastAPI)

```python
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

# ❌ VULNERABLE: Using ORM model directly
@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    return user  # Exposes ALL fields including password_hash!

# ✅ SECURE: Pydantic response models
class UserPublicResponse(BaseModel):
    """Public profile visible to all authenticated users"""
    id: int
    username: str
    email: EmailStr
    created_at: datetime
    
    class Config:
        from_attributes = True  # Formerly orm_mode

class UserPrivateResponse(UserPublicResponse):
    """User's own profile with additional private fields"""
    phone: Optional[str] = None
    address: Optional[str] = None
    email_verified: bool

class UserAdminResponse(UserPrivateResponse):
    """Admin view with management fields"""
    is_admin: bool
    is_active: bool
    last_login_at: Optional[datetime] = None
    failed_login_attempts: int

# Secure endpoint with response model
@app.get("/users/{user_id}", response_model=UserPublicResponse)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    # Pydantic automatically filters to only fields in response_model
    return user

@app.get("/users/me", response_model=UserPrivateResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/admin/users/{user_id}", response_model=UserAdminResponse)
def get_user_admin(
    user_id: int,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    return user
```

### Strategy 3: GraphQL Field-Level Permissions

```python
import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from graphql import GraphQLError

# ❌ VULNERABLE: All fields automatically exposed
class VulnerableUserType(SQLAlchemyObjectType):
    class Meta:
        model = User
        # All fields from model are queryable!

# ✅ SECURE: Explicit fields with authorization
class UserType(graphene.ObjectType):
    id = graphene.Int()
    username = graphene.String()
    email = graphene.String()
    
    # Sensitive fields with resolvers
    is_admin = graphene.Boolean()
    salary = graphene.Int()
    
    @staticmethod
    def resolve_is_admin(parent, info):
        """Only admins can see admin status"""
        current_user = info.context.get('current_user')
        if not current_user or not current_user.is_admin:
            raise GraphQLError("Unauthorized to access admin fields")
        return parent.is_admin
    
    @staticmethod
    def resolve_salary(parent, info):
        """Only user themselves or HR can see salary"""
        current_user = info.context.get('current_user')
        if not current_user:
            raise GraphQLError("Authentication required")
        
        if current_user.id != parent.id and not current_user.has_role('HR'):
            raise GraphQLError("Unauthorized to access salary information")
        
        return parent.salary

# Disable introspection in production
class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.Int())
    
    def resolve_user(self, info, id):
        return User.query.get(id)

# In production schema
schema = graphene.Schema(
    query=Query,
    auto_camelcase=False,
    # Disable introspection in production
    introspection=False if os.getenv('ENV') == 'production' else True
)
```

### Strategy 4: Field-Level Decorators

```python
from functools import wraps
from flask import current_app

def admin_only_field(func):
    """Decorator to restrict field access to admins"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            return None  # Or raise exception
        return func(*args, **kwargs)
    return wrapper

def owner_or_admin_field(func):
    """Field visible to owner or admin"""
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if current_user.id != user.id and not current_user.is_admin:
            return None
        return func(user, *args, **kwargs)
    return wrapper

class UserSchema(Schema):
    id = fields.Int()
    username = fields.Str()
    email = fields.Email()
    
    @admin_only_field
    def get_is_admin(self, obj):
        return obj.is_admin
    
    @owner_or_admin_field
    def get_salary(self, obj):
        return obj.salary
    
    is_admin = fields.Method('get_is_admin')
    salary = fields.Method('get_salary')
```

## Preventing Mass Assignment

### Strategy 1: Input Validation with Pydantic

```python
from pydantic import BaseModel, validator, Field
from typing import Optional

# ❌ VULNERABLE: No input validation
@app.put("/users/{user_id}")
def update_user(user_id: int, data: dict):  # Accepts any field!
    user = User.query.get_or_404(user_id)
    for key, value in data.items():
        setattr(user, key, value)  # Mass assignment vulnerability
    db.session.commit()
    return jsonify(user)

# ✅ SECURE: Explicit input model with allowlist
class UserUpdateRequest(BaseModel):
    """Only these fields can be updated by users"""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    
    # These fields are NOT in the model = cannot be set:
    # - is_admin
    # - salary
    # - role
    # - balance
    # - created_at
    # - updated_at
    
    @validator('username')
    def validate_username(cls, v):
        if v and not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

class UserAdminUpdateRequest(UserUpdateRequest):
    """Admins can update additional fields"""
    is_active: Optional[bool] = None
    role: Optional[str] = None
    # Still cannot update: salary, balance (separate endpoints)

@app.put("/users/{user_id}")
def update_user(
    user_id: int,
    update_data: UserUpdateRequest,  # Pydantic validates and filters
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    # Check authorization
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403)
    
    # Only update provided fields
    update_dict = update_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(user, key, value)
    
    db.session.commit()
    return user

@app.put("/admin/users/{user_id}")
def admin_update_user(
    user_id: int,
    update_data: UserAdminUpdateRequest,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    
    update_dict = update_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(user, key, value)
    
    db.session.commit()
    return user
```

### Strategy 2: Marshmallow with load_only

```python
from marshmallow import Schema, fields, validates, ValidationError

class UserUpdateSchema(Schema):
    """Schema for user updates - only accepts specific fields"""
    username = fields.Str(required=False, validate=Length(min=3, max=50))
    email = fields.Email(required=False)
    phone = fields.Str(required=False)
    
    # Use validate=... to add business logic
    @validates('email')
    def validate_email_unique(self, value):
        if User.query.filter_by(email=value).first():
            raise ValidationError('Email already in use')

class UserSchema(Schema):
    """Full schema with read-only fields"""
    id = fields.Int(dump_only=True)  # Cannot be set on load
    username = fields.Str()
    email = fields.Email()
    is_admin = fields.Bool(dump_only=True)  # Read-only!
    created_at = fields.DateTime(dump_only=True)  # Read-only!
    updated_at = fields.DateTime(dump_only=True)  # Read-only!

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    # Authorization check
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Use update schema (allowlist)
    schema = UserUpdateSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    
    # Safe to update - only allowed fields present
    for key, value in data.items():
        setattr(user, key, value)
    
    db.session.commit()
    
    # Return using full schema
    return jsonify(UserSchema().dump(user))
```

### Strategy 3: Explicit Update Methods

```python
class User(db.Model):
    # ... fields ...
    
    def update_profile(self, username=None, email=None, phone=None):
        """Safe update method - only allows specific fields"""
        if username is not None:
            self.username = username
        if email is not None:
            self.email = email
        if phone is not None:
            self.phone = phone
        # is_admin, salary, etc. cannot be updated here
    
    def admin_update(self, is_active=None, role=None):
        """Admin-only update method"""
        if is_active is not None:
            self.is_active = is_active
        if role is not None:
            self.role = role

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    if current_user.id != user_id:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # Use safe update method
    user.update_profile(
        username=data.get('username'),
        email=data.get('email'),
        phone=data.get('phone')
    )
    
    db.session.commit()
    return jsonify(UserPublicSchema().dump(user))

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_admin
def admin_update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # Admin can use admin update method
    user.admin_update(
        is_active=data.get('is_active'),
        role=data.get('role')
    )
    
    db.session.commit()
    return jsonify(UserAdminSchema().dump(user))
```

### Strategy 4: Immutable Fields

```python
from sqlalchemy.orm import validates

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Numeric(10, 2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    _protected_fields = ['is_admin', 'balance', 'created_at', 'id']
    
    @validates('is_admin')
    def validate_is_admin(self, key, value):
        """Prevent direct is_admin modification"""
        if self.id and not current_user.is_superadmin:
            raise ValueError('Cannot modify admin status')
        return value
    
    @validates('balance')
    def validate_balance(self, key, value):
        """Prevent direct balance modification"""
        raise ValueError('Cannot modify balance directly. Use transaction API.')
    
    @validates('created_at')
    def validate_created_at(self, key, value):
        """Prevent timestamp tampering"""
        if self.created_at:  # If already set
            return self.created_at  # Ignore new value
        return value
```

## Framework-Specific Implementations

### Django REST Framework

```python
from rest_framework import serializers
from django.contrib.auth.models import User

# ❌ VULNERABLE
class VulnerableUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # Exposes and accepts ALL fields!

# ✅ SECURE: Separate read and write serializers
class UserReadSerializer(serializers.ModelSerializer):
    """What users see in GET requests"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class UserWriteSerializer(serializers.ModelSerializer):
    """What users can update in PUT/PATCH requests"""
    class Meta:
        model = User
        fields = ['username', 'email']
    
    def validate_email(self, value):
        """Custom validation"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value

class UserAdminSerializer(serializers.ModelSerializer):
    """What admins see"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff', 
                  'is_active', 'date_joined', 'last_login']
        read_only_fields = ['id', 'date_joined', 'last_login']

# ViewSet with different serializers
from rest_framework import viewsets

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    
    def get_serializer_class(self):
        """Choose serializer based on action and user"""
        if self.action in ['create', 'update', 'partial_update']:
            if self.request.user.is_staff:
                return UserAdminSerializer
            return UserWriteSerializer
        
        if self.request.user.is_staff:
            return UserAdminSerializer
        return UserReadSerializer
```

### Express.js with TypeScript

```typescript
// ❌ VULNERABLE: No type safety or validation
app.put('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    Object.assign(user, req.body);  // Mass assignment!
    await user.save();
    res.json(user);  // Exposes all fields!
});

// ✅ SECURE: DTOs with class-validator
import { IsString, IsEmail, IsOptional, Length } from 'class-validator';
import { Exclude, Expose, plainToClass } from 'class-transformer';

// Response DTO
export class UserResponseDto {
    @Expose()
    id: number;
    
    @Expose()
    username: string;
    
    @Expose()
    email: string;
    
    @Expose()
    createdAt: Date;
    
    // Excluded fields (not in @Expose() = not serialized)
    // password_hash, isAdmin, salary, etc.
}

// Update DTO
export class UserUpdateDto {
    @IsOptional()
    @IsString()
    @Length(3, 50)
    username?: string;
    
    @IsOptional()
    @IsEmail()
    email?: string;
    
    // isAdmin, salary, etc. NOT included = cannot be set
}

// Admin Update DTO
export class UserAdminUpdateDto extends UserUpdateDto {
    @IsOptional()
    @IsBoolean()
    isActive?: boolean;
    
    @IsOptional()
    @IsString()
    role?: string;
}

// Secure endpoint
app.put('/api/users/:id', 
    authenticate,
    validateDto(UserUpdateDto),
    async (req, res) => {
        const userId = parseInt(req.params.id);
        
        // Authorization check
        if (req.user.id !== userId && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Safe update - only fields in DTO
        const updateDto = plainToClass(UserUpdateDto, req.body);
        Object.assign(user, updateDto);
        await user.save();
        
        // Safe response - only exposed fields
        const responseDto = plainToClass(UserResponseDto, user, {
            excludeExtraneousValues: true
        });
        
        res.json(responseDto);
    }
);

// Validation middleware
function validateDto(dtoClass: any) {
    return async (req, res, next) => {
        const dto = plainToClass(dtoClass, req.body);
        const errors = await validate(dto);
        
        if (errors.length > 0) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors
            });
        }
        
        next();
    };
}
```

### Ruby on Rails

```ruby
# app/models/user.rb
class User < ApplicationRecord
  # Strong parameters in controller handle mass assignment
  # Serializers handle output filtering
end

# app/controllers/api/users_controller.rb
class Api::UsersController < ApplicationController
  before_action :authenticate_user!
  before_action :set_user, only: [:show, :update]
  before_action :authorize_user!, only: [:update]
  
  def show
    render json: user_serializer.new(@user)
  end
  
  def update
    if @user.update(user_params)
      render json: user_serializer.new(@user)
    else
      render json: { errors: @user.errors }, status: :unprocessable_entity
    end
  end
  
  private
  
  def set_user
    @user = User.find(params[:id])
  end
  
  def authorize_user!
    unless current_user.id == @user.id || current_user.admin?
      render json: { error: 'Forbidden' }, status: :forbidden
    end
  end
  
  # ✅ SECURE: Strong parameters (allowlist)
  def user_params
    if current_user.admin?
      params.require(:user).permit(:username, :email, :is_active, :role)
    else
      params.require(:user).permit(:username, :email)
      # is_admin, salary, etc. NOT permitted
    end
  end
  
  def user_serializer
    if current_user.admin?
      UserAdminSerializer
    elsif current_user.id == @user.id
      UserPrivateSerializer
    else
      UserPublicSerializer
    end
  end
end

# app/serializers/user_public_serializer.rb
class UserPublicSerializer < ActiveModel::Serializer
  attributes :id, :username, :created_at
  # password_hash, is_admin, salary NOT included
end

# app/serializers/user_private_serializer.rb
class UserPrivateSerializer < UserPublicSerializer
  attributes :email, :phone
end

# app/serializers/user_admin_serializer.rb
class UserAdminSerializer < UserPrivateSerializer
  attributes :is_admin, :last_sign_in_at, :is_active
  # password_hash STILL not included
end
```

## Testing and Validation

### Automated Security Tests

```python
import pytest
from app import app, db
from models import User

class TestPropertyLevelAuthorization:
    
    def test_excessive_data_exposure(self, client, regular_user_token):
        """Test that sensitive fields are not exposed"""
        response = client.get(
            '/api/users/me',
            headers={'Authorization': f'Bearer {regular_user_token}'}
        )
        
        assert response.status_code == 200
        data = response.json
        
        # Should be present
        assert 'id' in data
        assert 'username' in data
        assert 'email' in data
        
        # Should NOT be present
        assert 'password_hash' not in data
        assert 'api_key' not in data
        assert 'is_admin' not in data
        assert 'salary' not in data
        assert 'ssn' not in data
    
    def test_mass_assignment_prevention(self, client, regular_user_token, regular_user):
        """Test that restricted fields cannot be modified"""
        malicious_data = {
            'username': 'updated',
            'is_admin': True,  # Should be rejected
            'salary': 999999,  # Should be rejected
            'balance': 1000000  # Should be rejected
        }
        
        response = client.put(
            f'/api/users/{regular_user.id}',
            json=malicious_data,
            headers={'Authorization': f'Bearer {regular_user_token}'}
        )
        
        # Reload user from database
        db.session.refresh(regular_user)
        
        # username should be updated
        assert regular_user.username == 'updated'
        
        # Restricted fields should NOT be modified
        assert regular_user.is_admin == False
        assert regular_user.salary != 999999
        assert regular_user.balance != 1000000
    
    def test_role_based_field_filtering(self, client, admin_token, regular_user_token):
        """Test that admins see more fields than regular users"""
        user_id = 1
        
        # Regular user view
        response = client.get(
            f'/api/users/{user_id}',
            headers={'Authorization': f'Bearer {regular_user_token}'}
        )
        regular_data = response.json
        
        # Admin view
        response = client.get(
            f'/api/users/{user_id}',
            headers={'Authorization': f'Bearer {admin_token}'}
        )
        admin_data = response.json
        
        # Admin sees additional fields
        assert 'is_admin' in admin_data
        assert 'last_login_ip' in admin_data
        
        # Regular user does not
        assert 'is_admin' not in regular_data
        assert 'last_login_ip' not in regular_data
        
        # Both should NOT see password_hash
        assert 'password_hash' not in regular_data
        assert 'password_hash' not in admin_data
    
    def test_read_only_fields(self, client, regular_user_token, regular_user):
        """Test that read-only fields cannot be modified"""
        response = client.put(
            f'/api/users/{regular_user.id}',
            json={
                'username': 'new_name',
                'created_at': '2020-01-01T00:00:00',  # Attempt to modify
                'id': 999  # Attempt to modify
            },
            headers={'Authorization': f'Bearer {regular_user_token}'}
        )
        
        db.session.refresh(regular_user)
        
        # username updated
        assert regular_user.username == 'new_name'
        
        # Read-only fields unchanged
        assert regular_user.id != 999
        assert regular_user.created_at != datetime(2020, 1, 1)
```

### Manual Testing Checklist

```bash
# Test 1: Excessive Data Exposure
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/v1/users/me | \
  jq 'keys'  # Check for sensitive fields

# Test 2: Mass Assignment - Privilege Escalation
curl -X PUT https://api.example.com/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true, "role": "admin"}'

# Verify user is NOT admin after request

# Test 3: Mass Assignment - Financial Fields
curl -X PUT https://api.example.com/v1/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"balance": 1000000, "salary": 999999}'

# Verify fields not modified

# Test 4: GraphQL Introspection
curl -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name fields{name}}}}"}'

# Should be disabled in production or show limited fields

# Test 5: Different User Roles
# As regular user
curl -H "Authorization: Bearer $REGULAR_TOKEN" \
  https://api.example.com/v1/users/1 | jq 'keys'

# As admin
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://api.example.com/v1/users/1 | jq 'keys'

# Admins should see more fields, but NOT password_hash
```

## Security Checklist

### Development Phase

- [ ] Define separate DTOs for input and output
- [ ] Use allowlists for updatable fields
- [ ] Mark sensitive fields as `dump_only` (read-only)
- [ ] Never serialize database models directly
- [ ] Implement role-based serializers
- [ ] Use schema validation libraries
- [ ] Create explicit update methods
- [ ] Document which roles can access each field
- [ ] Use TypeScript/type hints for compile-time checks
- [ ] Disable GraphQL introspection in production

### Testing Phase

- [ ] Test API responses for sensitive field exposure
- [ ] Attempt mass assignment on all endpoints
- [ ] Test with different user roles
- [ ] Verify read-only fields cannot be modified
- [ ] Check GraphQL field-level permissions
- [ ] Test batch/bulk endpoints
- [ ] Verify error messages don't leak field names
- [ ] Test with invalid/unexpected fields
- [ ] Check for parameter pollution vulnerabilities
- [ ] Automated tests for each sensitive field

### Deployment Phase

- [ ] Code review focused on serializers
- [ ] Security scan for direct model serialization
- [ ] Verify production DTOs match documentation
- [ ] Enable field access logging for sensitive data
- [ ] Configure monitoring for anomalous field access
- [ ] Disable debug mode and verbose errors
- [ ] Review API documentation for exposed fields
- [ ] Penetration testing specifically for API03
- [ ] Set up alerts for mass assignment attempts
- [ ] Regular audits of serializer definitions

### Ongoing Maintenance

- [ ] Review serializers when adding new fields
- [ ] Audit field exposure after model changes
- [ ] Regular security assessments
- [ ] Monitor logs for unauthorized field access
- [ ] Update DTOs when requirements change
- [ ] Keep validation libraries up to date
- [ ] Review and update documentation
- [ ] Train developers on secure serialization
- [ ] Incident response plan for data exposure
- [ ] Regular penetration testing

## What's Next?

- **[Examples](./examples.md)**: See complete code examples of vulnerable and secure implementations
- **[Lab](./lab/api03-mass-assignment-lab/)**: Practice identifying and fixing property-level authorization issues
- **[Attack Vectors](./attack-vectors.md)**: Review common attack patterns

---

*Part of the [OWASP API Security Top 10 Educational Repository](../../README.md)*
